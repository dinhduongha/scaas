//! cargo test --test e2e_aptos -- --ignored --nocapture
//!
//! Cần localnet Aptos đã chạy và đã publish: `chains/aptos/scripts/devnet.sh up && … publish` (REST 32010, faucet
//! 32011, Indexer API 32015 — dải cổng của luồng S11; thư mục `$APTOS_LOCALNET_DIR`). Chứng minh:
//! 1. hai lane relayer từ mnemonic 24 từ (`m/44'/637'/i'/0'/0'`), nạp từ faucet; alice (chủ thể) không có APT;
//! 2. FA thử thật (`testfa`); Odoo giả trả địa chỉ metadata thật và TỪ CHỐI event của token chưa đăng ký;
//! 3. ANTI-LOCK đồng thời: X đã `signed` trên lane 0 nhưng bị GIỮ chưa gửi; Y đi hết tới `mined` trên lane 1; rồi X
//!    được thả và qua; phát lại X ⇒ mô phỏng từ chối ⇒ `dead`; hash tx tự tính = `hash` của REST;
//! 4. `Rejected`: tx ký với sequence cũ bị REST từ chối trước mempool ⇒ `adapter::Rejected`;
//! 5. khởi động lại: job `broadcast` trước crash được `recover_lane` chốt `mined`; job `signed` chưa gửi hết hạn ⇒
//!    `dead`;
//! 6. `index_step` (Indexer API + fullnode) báo `PaymentSettled` + `MetaTransactionExecuted` (digest = digest đã ký);
//!    event của một package bản sao và của FA chưa đăng ký bị bỏ; danh sách token rỗng ⇒ con trỏ đứng yên.
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::extract::{Path, State};
use axum::routing::post;
use axum::{Json, Router};
use bamboo_node::adapter::{index_step, lane_step, recover_lane, Built, ChainAdapter, Family, Head, Lane, Rejected, Signed, TxStatus};
use bamboo_node::adapters::aptos::{account_of, addr_hex, lane_address, object_address, parse_addr, sha3, Addr, MetaOp};
use bamboo_node::chain::SimError;
use bamboo_node::config::{ChainCfg, FinalityCfg, OdooCfg};
use bamboo_node::keys::{lane_secret, Seed};
use bamboo_node::odoo::{Job, Odoo};
use bamboo_node::signer::{Curve, LocalSigner, Signer};
use serde_json::{json, Value};

const REST: &str = "http://127.0.0.1:32010/v1";
const FAUCET: &str = "http://127.0.0.1:32011";
const GQL: &str = "http://127.0.0.1:32015/v1/graphql";
const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
const SHOP: &str = "0x5e";

fn dir() -> PathBuf {
    std::env::var("APTOS_LOCALNET_DIR").unwrap_or_else(|_| "/tmp/bamboo-aptos-localnet".into()).into()
}

fn read(name: &str) -> String {
    std::fs::read_to_string(dir().join(name)).unwrap_or_else(|e| panic!("{name}: {e} (run devnet.sh up && publish)")).trim().into()
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

fn sha256(b: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(b).into()
}

async fn get(path: &str) -> Value {
    reqwest::get(format!("{REST}{path}")).await.unwrap().json().await.unwrap()
}

async fn balance(owner: &Addr, asset: &str) -> u64 {
    let body = json!({"function": "0x1::primary_fungible_store::balance", "type_arguments": ["0x1::object::ObjectCore"],
        "arguments": [addr_hex(owner), asset]});
    let v: Value = reqwest::Client::new().post(format!("{REST}/view")).json(&body).send().await.unwrap().json().await.unwrap();
    v[0].as_str().unwrap_or_else(|| panic!("balance: {v}")).parse().unwrap()
}

async fn fund(a: &Addr) {
    let r = reqwest::Client::new().post(format!("{FAUCET}/mint?amount=1000000000&address={}", addr_hex(a))).send().await.unwrap();
    assert!(r.status().is_success(), "faucet: {}", r.text().await.unwrap());
    for _ in 0..60 {
        if balance(a, "0xa").await > 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("faucet APT never arrived");
}

/// Tx native của deployer qua CLI (chỉ dựng môi trường, KHÔNG phải đường relayer).
fn cli(function: &str, args: &[String]) {
    let mut c = Command::new("aptos");
    c.current_dir(dir().join("cli")).args(["move", "run", "--profile", "deployer", "--assume-yes", "--function-id", function, "--args"]);
    c.args(args);
    let out = c.output().expect("aptos in PATH");
    assert!(out.status.success(), "{function}: {}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
}

// ------------------------------------------------------------------ fake Odoo (same transitions as e2e.rs)

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
    ingests: u32,
    indexed_block: u64,
    /// `blockchain.token.address` = địa chỉ metadata FA thật (L1/L2: indexer lọc theo đây).
    tokens: Vec<String>,
    inflight: Vec<Value>,
}

async fn fake(State(s): State<Arc<Mutex<FakeOdoo>>>, Path((model, method)): Path<(String, String)>, Json(body): Json<Value>) -> Json<Value> {
    let mut o = s.lock().unwrap();
    let out = match (model.as_str(), method.as_str()) {
        ("blockchain.chain", "node_config") => json!({
            "finality_mode": "instant", "finality_depth": 0, "finality_quorum": 1, "indexed_block": o.indexed_block,
            "tokens": o.tokens.iter().map(|a| json!({"address": a, "decimals": 6})).collect::<Vec<_>>(),
            "journal_max_nonce": null, "inflight": std::mem::take(&mut o.inflight)}),
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
            // Như Odoo thật: event của contract chưa đăng ký bị từ chối (L2).
            for e in body["events"].as_array().unwrap() {
                if !o.tokens.iter().any(|t| Some(t.as_str()) == e["contract"].as_str()) {
                    o.refused.push(e.clone());
                }
            }
            o.ingests += 1;
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
    let cfg = OdooCfg { url: format!("http://{addr}"), database: "t".into(), relay_api_key_env: String::new(), indexer_api_key_env: String::new() };
    Odoo::with_key(&cfg, "k".into()).unwrap()
}

/// Một `pay` của alice ký qua phong bì signMessage tối thiểu (ví seed R32) thành job `signed_op`.
#[allow(clippy::too_many_arguments)]
fn job(id: i64, alice: &LocalSigner, pkg: &Addr, asset: &str, amount: u128, ref_byte: u8, lane_byte: u8, valid_until: u64) -> (Value, [u8; 32]) {
    let from = lane_address(&alice.public_key());
    let op = MetaOp {
        chain_id: 4,
        contract: account_of(pkg, &from),
        asset: parse_addr(asset).unwrap(),
        op: 0,
        from,
        to: parse_addr(SHOP).unwrap(),
        amount,
        pay_ref: vec![ref_byte; 32],
        lane: vec![lane_byte; 32],
        nonce: 0,
        valid_until,
        relayer: [0u8; 32],
        extra: vec![0u8; 32],
    };
    let payload = op.encode();
    let digest = sha3(&payload);
    let env = format!("APTOS\nmessage: bamboo.metaop.v1:0x{}\nnonce: {}", alloy::hex::encode(digest), alloy::hex::encode(&op.lane));
    let mut blob = alice.sign(env.as_bytes()).unwrap();
    blob.extend_from_slice(env.as_bytes());
    let j = json!({"id": id, "kind": "signed_op", "op": {
        "family": "aptos", "contract": addr_hex(&op.contract), "from": addr_hex(&from), "op_kind": "pay",
        "payload": alloy::hex::encode(&payload), "signature": alloy::hex::encode(&blob),
        "public_key": alloy::hex::encode(alice.public_key()), "auth_kind": "wallet", "digest": addr_hex(&digest),
        "valid_until": valid_until, "extra": {"asset": asset}}});
    (j, digest)
}

/// Adapter thật, nhưng `submit` của job `hold` chờ tới khi test thả `gate` (tx đã ký + đã journal `signed`).
struct Held {
    inner: Arc<dyn ChainAdapter>,
    hold: i64,
    gate: tokio::sync::Semaphore,
}

#[async_trait]
impl ChainAdapter for Held {
    fn family(&self) -> Family {
        self.inner.family()
    }
    fn chain_key(&self) -> &str {
        self.inner.chain_key()
    }
    fn lanes(&self) -> &[Lane] {
        self.inner.lanes()
    }
    async fn build(&self, job: &Job, lane: usize) -> Result<Built, SimError> {
        self.inner.build(job, lane).await
    }
    async fn sign(&self, b: Built, lane: usize, seq: u64) -> anyhow::Result<Signed> {
        self.inner.sign(b, lane, seq).await
    }
    async fn submit(&self, s: &Signed) -> anyhow::Result<()> {
        if s.job_id == self.hold {
            self.gate.acquire().await.unwrap().forget();
        }
        self.inner.submit(s).await
    }
    async fn tx_status(&self, tx: &str) -> anyhow::Result<TxStatus> {
        self.inner.tx_status(tx).await
    }
    async fn sequence(&self, lane: usize) -> anyhow::Result<u64> {
        self.inner.sequence(lane).await
    }
    async fn final_head(&self) -> anyhow::Result<Option<Head>> {
        self.inner.final_head().await
    }
    async fn block_hash(&self, h: u64) -> anyhow::Result<String> {
        self.inner.block_hash(h).await
    }
    async fn events(&self, from: u64, to: u64, contracts: &[String]) -> anyhow::Result<Vec<Value>> {
        self.inner.events(from, to, contracts).await
    }
}

fn states_of(state: &Arc<Mutex<FakeOdoo>>, id: i64) -> Vec<String> {
    state.lock().unwrap().reports.iter().filter(|r| r["job_id"] == id).map(|r| r["chain_state"].as_str().unwrap().to_string()).collect()
}

async fn run_job(adapter: &dyn ChainAdapter, odoo: &Odoo, state: &Arc<Mutex<FakeOdoo>>, lane: usize, j: Value) -> Vec<String> {
    let id = j["id"].as_i64().unwrap();
    state.lock().unwrap().jobs.push(j);
    assert!(lane_step(adapter, odoo, lane, "e2e").await.unwrap());
    states_of(state, id)
}

fn cfg(package: &str) -> ChainCfg {
    let mut params = toml::Table::new();
    params.insert("package".into(), toml::Value::String(package.into()));
    params.insert("indexer_url".into(), toml::Value::String(GQL.into()));
    params.insert("tx_ttl_s".into(), toml::Value::Integer(120));
    ChainCfg {
        family: "aptos".into(),
        network: Some("4".into()),
        rpc_urls: vec![REST.into()],
        lanes: vec![0, 1],
        params,
        finality: FinalityCfg { mode: "instant".into(), depth: 0, quorum: 1 },
        poll_ms: 200,
        ..Default::default()
    }
}

#[tokio::test]
#[ignore]
async fn aptos_payments_relay_finalize_and_never_lock_each_other() {
    let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();
    let (pkg, copy, deployer) = (read("package.txt"), read("copy.txt"), read("deployer.txt"));
    let (pkg_a, copy_a) = (parse_addr(&pkg).unwrap(), parse_addr(&copy).unwrap());
    assert_eq!(get("").await["chain_id"], 4);

    // FA thật do deployer tạo; alice (chủ thể) KHÔNG có APT, tiền nằm ở Account derived của nó.
    let busd = addr_hex(&object_address(&parse_addr(&deployer).unwrap(), b"BUSD"));
    let evil = addr_hex(&object_address(&parse_addr(&deployer).unwrap(), b"EVIL"));
    let alice = LocalSigner::new(Curve::Ed25519, &sha256(b"alice")).unwrap();
    let alice_addr = lane_address(&alice.public_key());
    let (acct, acct_copy) = (account_of(&pkg_a, &alice_addr), account_of(&copy_a, &alice_addr));
    cli(&format!("{deployer}::coin::create"), &["hex:42555344".into()]);
    cli(&format!("{deployer}::coin::create"), &["hex:4556494c".into()]);
    for (a, sym) in [(acct, "42555344"), (acct_copy, "42555344"), (acct, "4556494c")] {
        cli(&format!("{deployer}::coin::mint"), &[format!("hex:{sym}"), format!("address:{}", addr_hex(&a)), "u64:100000".into()]);
    }
    assert_eq!(balance(&acct, &busd).await, 100_000);
    assert_eq!(balance(&alice_addr, "0xa").await, 0, "alice has no gas at all");

    // Hai lane từ mnemonic 24 từ.
    let seed = Seed::from_words(MNEMONIC, None).unwrap();
    let signers: Vec<LocalSigner> = [0u32, 1]
        .iter()
        .map(|&i| {
            let (curve, secret) = lane_secret(&seed, "aptos", i).unwrap();
            LocalSigner::new(curve, &secret).unwrap()
        })
        .collect();
    for s in &signers {
        fund(&lane_address(&s.public_key())).await;
    }
    let adapter = bamboo_node::adapters::build(&cfg(&pkg), &signers).unwrap();
    assert_eq!(adapter.chain_key(), "aptos:4");
    assert_eq!(adapter.lanes()[0].address, "0x226b5b5c15d19946b1fd26c3e4ad36833fd8c9c11c612b1327e608f824a5f2d4");
    assert!(adapter.lane_balance(0).await.unwrap().unwrap() > 0);

    let state = Arc::new(Mutex::new(FakeOdoo { tokens: vec![busd.clone()], ..Default::default() }));
    let odoo = odoo_at(start_fake(state.clone()).await);
    let mut head0 = None;
    for _ in 0..60 {
        head0 = adapter.final_head().await.unwrap();
        if head0.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    state.lock().unwrap().indexed_block = head0.expect("indexer never reported progress").height;

    // ANTI-LOCK đồng thời: X `signed` trên lane 0 và bị giữ; Y (lane Odoo khác) đi hết trên lane 1.
    let vu = now() + 300;
    let (x, x_digest) = job(1, &alice, &pkg_a, &busd, 1000, 0x11, 0xa1, vu);
    let (y, y_digest) = job(2, &alice, &pkg_a, &busd, 500, 0x22, 0xa2, vu);
    let held = Held { inner: adapter.clone(), hold: 1, gate: tokio::sync::Semaphore::new(0) };
    state.lock().unwrap().jobs.push(x.clone());
    let x_run = lane_step(&held, &odoo, 0, "e2e");
    let y_run = async {
        while states_of(&state, 1).last().map(String::as_str) != Some("signed") {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        state.lock().unwrap().jobs.push(y);
        assert!(lane_step(&held, &odoo, 1, "e2e").await.unwrap());
        assert_eq!(states_of(&state, 2), ["signed", "broadcast", "mined"], "Y while X is in flight");
        assert_eq!(states_of(&state, 1), ["signed"], "X still held, unsent");
        held.gate.add_permits(1);
    };
    let joined = tokio::time::timeout(Duration::from_secs(120), async { tokio::join!(x_run, y_run) }).await;
    let Ok((x_done, ())) = joined else { panic!("lanes stuck: {:#?}", state.lock().unwrap().reports) };
    assert!(x_done.unwrap());
    assert_eq!(states_of(&state, 1), ["signed", "broadcast", "mined"]);
    assert_eq!(balance(&parse_addr(SHOP).unwrap(), &busd).await, 1500);
    // Hash tự tính trước khi gửi = hash REST (RS11-7).
    let x_hash = state.lock().unwrap().reports.iter().find(|r| r["job_id"] == 1 && r["chain_state"] == "signed").unwrap()["tx_hash"].clone();
    let x_tx = get(&format!("/transactions/by_hash/{}", x_hash.as_str().unwrap())).await;
    assert_eq!(x_tx["hash"], x_hash);
    assert_eq!(x_tx["success"], true);
    // Phát lại X: mô phỏng abort (nonce lane đã dùng) ⇒ dead, không tốn gas.
    let mut replay = x;
    replay["id"] = json!(3);
    assert_eq!(run_job(adapter.as_ref(), &odoo, &state, 0, replay).await, ["dead"]);

    // REJECTED: ký với sequence cũ ⇒ REST từ chối trước mempool.
    let (r6, _) = job(6, &alice, &pkg_a, &busd, 10, 0x66, 0xa6, vu);
    let r6: Job = serde_json::from_value(r6).unwrap();
    let seq = adapter.sequence(0).await.unwrap();
    let stale = adapter.sign(adapter.build(&r6, 0).await.unwrap(), 0, seq - 1).await.unwrap();
    let err = adapter.submit(&stale).await.unwrap_err();
    assert!(err.downcast_ref::<Rejected>().is_some(), "{err:#}");
    assert!(format!("{err}").contains("SEQUENCE_NUMBER_TOO_OLD"), "{err:#}");
    assert_eq!(adapter.tx_status(&stale.tx_id).await.unwrap(), TxStatus::Unknown);

    // KHỞI ĐỘNG LẠI (merge TODO b). A: job đã `broadcast` trước crash ⇒ `recover_lane` của tiến trình mới chốt mined.
    let (a7, _) = job(7, &alice, &pkg_a, &busd, 70, 0x77, 0xa7, vu);
    let a7: Job = serde_json::from_value(a7).unwrap();
    let seq = adapter.sequence(0).await.unwrap();
    let s7 = adapter.sign(adapter.build(&a7, 0).await.unwrap(), 0, seq).await.unwrap();
    adapter.submit(&s7).await.unwrap();
    // B: job `signed` (journal) nhưng chưa gửi, payload sắp hết hạn ⇒ không bao giờ vào sổ ⇒ dead.
    let (b8, _) = job(8, &alice, &pkg_a, &busd, 80, 0x88, 0xa8, now() + 3);
    let b8: Job = serde_json::from_value(b8).unwrap();
    let s8 = adapter.sign(adapter.build(&b8, 1).await.unwrap(), 1, adapter.sequence(1).await.unwrap()).await.unwrap();
    drop(adapter);
    let adapter = bamboo_node::adapters::build(&cfg(&pkg), &signers).unwrap(); // tiến trình mới
    {
        let mut o = state.lock().unwrap();
        o.states.insert(7, "broadcast".into());
        o.states.insert(8, "signed".into());
        o.inflight = vec![json!({"job_id": 7, "state": "broadcast", "tx_hash": s7.tx_id, "nonce": s7.sequence,
            "payload": {"id": 7, "kind": "signed_op", "op": {"valid_until": vu}}})];
    }
    tokio::time::timeout(Duration::from_secs(60), recover_lane(adapter.as_ref(), &odoo, 0, "e2e")).await.expect("recovery A").unwrap();
    assert_eq!(states_of(&state, 7), ["mined"]);
    state.lock().unwrap().inflight = vec![json!({"job_id": 8, "state": "signed", "tx_hash": s8.tx_id, "nonce": s8.sequence,
        "payload": {"id": 8, "kind": "signed_op", "op": {"valid_until": s8.valid_until}}})];
    tokio::time::timeout(Duration::from_secs(90), recover_lane(adapter.as_ref(), &odoo, 1, "e2e")).await.expect("recovery B").unwrap();
    assert_eq!(states_of(&state, 8), ["dead"]);

    // L2: thanh toán qua package BẢN SAO (cùng token đã đăng ký) và qua FA chưa đăng ký đều vào sổ nhưng không được báo.
    let copy_adapter = bamboo_node::adapters::build(&cfg(&copy), &signers).unwrap();
    let (c9, _) = job(9, &alice, &copy_a, &busd, 90, 0x99, 0xa9, vu);
    assert_eq!(run_job(copy_adapter.as_ref(), &odoo, &state, 1, c9).await, ["signed", "broadcast", "mined"]);
    let (e10, _) = job(10, &alice, &pkg_a, &evil, 33, 0xaa, 0xaa, vu);
    assert_eq!(run_job(adapter.as_ref(), &odoo, &state, 1, e10).await, ["signed", "broadcast", "mined"]);

    // Final: index tới khi thấy X, Y, A (cursor không vượt Indexer API).
    for _ in 0..120 {
        while index_step(adapter.as_ref(), &odoo).await.unwrap() {}
        if state.lock().unwrap().ingested.iter().filter(|e| e["event"] == "PaymentSettled").count() >= 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let ing = state.lock().unwrap().ingested.clone();
    let shop = addr_hex(&parse_addr(SHOP).unwrap());
    let settled: Vec<&Value> = ing.iter().filter(|e| e["event"] == "PaymentSettled").collect();
    assert_eq!(settled.len(), 3, "X, Y, A only — not the copy package, not EVIL: {ing:#?}");
    let pay_x = settled.iter().find(|e| e["entry_ref"] == addr_hex(&[0x11u8; 32])).expect("X settled");
    assert_eq!((pay_x["contract"].as_str(), pay_x["to"].as_str(), pay_x["amount"].as_str()), (Some(busd.as_str()), Some(shop.as_str()), Some("1000")));
    assert_eq!(pay_x["from"], addr_hex(&alice_addr));
    assert_eq!(pay_x["tx_hash"], x_hash);
    for d in [x_digest, y_digest] {
        assert!(ing.iter().any(|e| e["event"] == "MetaTransactionExecuted" && e["digest"] == addr_hex(&d)), "digest {}", addr_hex(&d));
    }
    assert!(ing.iter().all(|e| e["block_hash"].as_str().unwrap().len() == 66 && e["contract"] == busd));
    assert!(state.lock().unwrap().refused.is_empty(), "{:#?}", state.lock().unwrap().refused);

    // Danh sách token rỗng ⇒ không ingest, con trỏ đứng yên (L1).
    let (cursor, ingests) = {
        let mut o = state.lock().unwrap();
        o.tokens.clear();
        o.indexed_block = o.indexed_block.saturating_sub(5);
        (o.indexed_block, o.ingests)
    };
    assert!(!index_step(adapter.as_ref(), &odoo).await.unwrap());
    let o = state.lock().unwrap();
    assert_eq!((o.indexed_block, o.ingests), (cursor, ingests));
    println!("gas: X {} units at {} octa", x_tx["gas_used"], x_tx["gas_unit_price"]);
}
