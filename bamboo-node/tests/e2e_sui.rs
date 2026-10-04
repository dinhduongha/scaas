//! cargo test --test e2e_sui -- --ignored --nocapture
//!
//! Cần `sui` (1.81+) trong PATH. Localnet thật: `sui start --force-regenesis` (RPC 31970, faucet 31971 —
//! dải cổng của luồng S7). Chứng minh:
//! 1. publish `chains/sui` + coin thử, mở `Account<SUI>`/`Account<DEMO>` cho alice (alice không có gas);
//! 2. hai lane relayer từ mnemonic 24 từ (`m/44'/784'/i'/0'/0'`), job `signed_op` (giả Odoo) đi qua
//!    `lane_step`: dry-run → ký → `signed` trước khi gửi → mined;
//! 3. ANTI-LOCK: alice ký X (account SUI) và Y (account DEMO); X bị giữ; Y qua; rồi X qua;
//!    phát lại X ⇒ dry-run từ chối ⇒ `dead`;
//! 4. `index_step` báo `PaymentSettled` + `MetaTransactionExecuted` (digest = digest đã ký) vùng final.
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Path, State};
use axum::routing::post;
use axum::{Json, Router};
use bamboo_node::adapter::{index_step, lane_step, ChainAdapter};
use bamboo_node::adapters::sui::{addr_hex, lane_address, parse_addr, personal_digest, tx_signing_digest, Addr, MetaOp};
use bamboo_node::config::{ChainCfg, FinalityCfg, OdooCfg};
use bamboo_node::keys::{lane_secret, Seed};
use bamboo_node::odoo::Odoo;
use bamboo_node::signer::{Curve, LocalSigner, Signer};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};

const RPC: &str = "http://127.0.0.1:31970";
const FAUCET: &str = "http://127.0.0.1:31971";
const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
const SHOP: &str = "0x5e";

struct Net(Child);
impl Drop for Net {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

fn sha256(b: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(b).into()
}

async fn rpc(method: &str, params: Value) -> Value {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    let v: Value = reqwest::Client::new().post(RPC).json(&body).send().await.unwrap().json().await.unwrap();
    assert!(v.get("error").is_none(), "{method}: {v}");
    v["result"].clone()
}

async fn start_localnet() -> Net {
    let child = Command::new("sui")
        .args(["start", "--force-regenesis", "--with-faucet=127.0.0.1:31971", "--fullnode-rpc-port", "31970"])
        .env("RUST_LOG", "error")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("sui in PATH");
    let net = Net(child);
    for _ in 0..120 {
        tokio::time::sleep(Duration::from_millis(1000)).await;
        let ok = reqwest::Client::new()
            .post(format!("{FAUCET}/v2/gas"))
            .json(&json!({"FixedAmountRequest": {"recipient": addr_hex(&[0u8; 32])}}))
            .send()
            .await
            .is_ok_and(|r| r.status().is_success());
        if ok {
            return net;
        }
    }
    panic!("localnet did not come up");
}

async fn faucet(to: &Addr) {
    let r = reqwest::Client::new()
        .post(format!("{FAUCET}/v2/gas"))
        .json(&json!({"FixedAmountRequest": {"recipient": addr_hex(to)}}))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "faucet: {}", r.text().await.unwrap());
    for _ in 0..60 {
        let c = rpc("suix_getCoins", json!([addr_hex(to), "0x2::sui::SUI", null, 50])).await;
        if !c["data"].as_array().unwrap().is_empty() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("faucet coins never arrived");
}

/// Ký + gửi tx (bytes do RPC dựng — chỉ dùng cho bước dựng môi trường, KHÔNG phải đường relayer).
async fn exec(key: &LocalSigner, tx_b64: &str) -> Value {
    let tx = B64.decode(tx_b64).unwrap();
    let mut sig = vec![0u8];
    sig.extend(key.sign(&tx_signing_digest(&tx)).unwrap());
    sig.extend(key.public_key());
    let r = rpc("sui_executeTransactionBlock", json!([tx_b64, [B64.encode(&sig)],
        {"showEffects": true, "showObjectChanges": true}, "WaitForLocalExecution"])).await;
    assert_eq!(r["effects"]["status"]["status"], "success", "{r}");
    r
}

async fn call(key: &LocalSigner, sender: &Addr, pkg: &str, module: &str, func: &str, tys: Value, args: Value) -> Value {
    let t = rpc("unsafe_moveCall", json!([addr_hex(sender), pkg, module, func, tys, args, null, "100000000"])).await;
    exec(key, t["txBytes"].as_str().unwrap()).await
}

fn created(r: &Value, ty_contains: &str) -> String {
    r["objectChanges"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["type"] == "created" && c["objectType"].as_str().unwrap_or("").contains(ty_contains))
        .unwrap_or_else(|| panic!("no created {ty_contains} in {r}"))["objectId"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn publish(key: &LocalSigner, sender: &Addr, dir: &str) -> Value {
    let out = Command::new("sui").args(["move", "build", "--dump-bytecode-as-base64", "--path", dir]).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let text = String::from_utf8(out.stdout).unwrap();
    let b: Value = serde_json::from_str(&text[text.find('{').unwrap()..]).unwrap();
    let t = rpc("unsafe_publish", json!([addr_hex(sender), b["modules"], b["dependencies"], null, "500000000"])).await;
    exec(key, t["txBytes"].as_str().unwrap()).await
}

fn published(r: &Value) -> String {
    r["objectChanges"].as_array().unwrap().iter().find(|c| c["type"] == "published").unwrap()["packageId"]
        .as_str()
        .unwrap()
        .to_string()
}

fn bytes(b: &[u8]) -> Value {
    json!(b.iter().map(|x| *x as u64).collect::<Vec<_>>())
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
    indexed_block: u64,
    /// `blockchain.token.address` của chain = id `Registry<T>` thật (review H1/H2: indexer lọc theo đây).
    tokens: Vec<String>,
}

async fn fake(State(s): State<Arc<Mutex<FakeOdoo>>>, Path((model, method)): Path<(String, String)>, Json(body): Json<Value>) -> Json<Value> {
    let mut o = s.lock().unwrap();
    let out = match (model.as_str(), method.as_str()) {
        ("blockchain.chain", "node_config") => json!({
            "evm_chain_number": body["evm_chain_number"], "finality_mode": "instant", "finality_depth": 0,
            "finality_quorum": 1, "indexed_block": o.indexed_block,
            "tokens": o.tokens.iter().map(|a| json!({"address": a, "decimals": 9})).collect::<Vec<_>>(), "journal_max_nonce": null,
            "inflight": []}),
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
    let cfg = OdooCfg { url: format!("http://{addr}"), database: "t".into(), relay_api_key_env: String::new(), indexer_api_key_env: String::new() };
    Odoo::with_key(&cfg, "k".into()).unwrap()
}

/// Một payment `pay` của alice đã ký (serialized ed25519) thành job `signed_op`.
fn job(id: i64, alice: &LocalSigner, account: &str, coin_type: &str, amount: u128, ref_byte: u8, lane_byte: u8) -> (Value, [u8; 32]) {
    let op = MetaOp {
        network: b"localnet".to_vec(),
        contract: parse_addr(account).unwrap(),
        op: 0,
        from: lane_address(&alice.public_key()),
        to: parse_addr(SHOP).unwrap(),
        amount,
        pay_ref: vec![ref_byte; 32],
        lane: vec![lane_byte; 32],
        nonce: 0,
        valid_until: now() + 300,
        relayer: [0u8; 32],
        extra: vec![0u8; 32],
    };
    let payload = op.encode();
    let digest = personal_digest(&payload);
    let mut sig = vec![0u8];
    sig.extend(alice.sign(&digest).unwrap());
    sig.extend(alice.public_key());
    let j = json!({"id": id, "kind": "signed_op", "op": {
        "family": "sui", "contract": account, "from": addr_hex(&op.from), "op_kind": "pay",
        "payload": alloy::hex::encode(&payload), "signature": B64.encode(&sig), "public_key": null, "auth_kind": "wallet",
        "digest": addr_hex(&digest), "valid_until": op.valid_until, "extra": {"coin_type": coin_type}}});
    (j, digest)
}

async fn run_job(adapter: &dyn ChainAdapter, odoo: &Odoo, state: &Arc<Mutex<FakeOdoo>>, lane: usize, j: Value) -> Vec<String> {
    let id = j["id"].as_i64().unwrap();
    state.lock().unwrap().jobs.push(j);
    assert!(lane_step(adapter, odoo, lane, "e2e").await.unwrap());
    let reports = state.lock().unwrap().reports.clone();
    reports.iter().filter(|r| r["job_id"] == id).map(|r| r["chain_state"].as_str().unwrap().to_string()).collect()
}

#[tokio::test]
#[ignore]
async fn sui_payments_relay_finalize_and_never_lock_each_other() {
    let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();
    let _net = start_localnet().await;
    let root_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../chains/sui");

    // Deployer (môi trường) và alice (chủ thể: KHÔNG bao giờ có gas).
    let deployer = LocalSigner::new(Curve::Ed25519, &sha256(b"deployer")).unwrap();
    let dep = lane_address(&deployer.public_key());
    let alice = LocalSigner::new(Curve::Ed25519, &sha256(b"alice")).unwrap();
    let alice_addr = lane_address(&alice.public_key());
    faucet(&dep).await;

    let p = publish(&deployer, &dep, root_dir).await;
    let pkg = published(&p);
    let (root, cap) = (created(&p, "::meta::Root"), created(&p, "::meta::AdminCap"));
    let d = publish(&deployer, &dep, &format!("{root_dir}/demo_coin")).await;
    let demo_pkg = published(&d);
    let treasury = created(&d, "TreasuryCap");
    let demo_t = format!("{demo_pkg}::demo::DEMO");

    call(&deployer, &dep, &pkg, "meta", "set_network", json!([]), json!([cap, root, bytes(b"localnet")])).await;
    let r = call(&deployer, &dep, &pkg, "meta", "new_registry", json!(["0x2::sui::SUI"]), json!([root])).await;
    let reg_sui = created(&r, "::meta::Registry<");
    let r = call(&deployer, &dep, &pkg, "meta", "new_registry", json!([demo_t]), json!([root])).await;
    let reg_demo = created(&r, "::meta::Registry<");
    let r = call(&deployer, &dep, &pkg, "meta", "open", json!(["0x2::sui::SUI"]), json!([reg_sui, 0, bytes(&alice.public_key())])).await;
    let acct_sui = created(&r, "::meta::Account<");
    let r = call(&deployer, &dep, &pkg, "meta", "open", json!([demo_t]), json!([reg_demo, 0, bytes(&alice.public_key())])).await;
    let acct_demo = created(&r, "::meta::Account<");

    // Nạp: SUI tách từ coin của deployer; DEMO đúc rồi nạp.
    let coins = rpc("suix_getCoins", json!([addr_hex(&dep), "0x2::sui::SUI", null, 50])).await;
    let big = coins["data"][0]["coinObjectId"].as_str().unwrap().to_string();
    let t = rpc("unsafe_splitCoin", json!([addr_hex(&dep), big, ["5000000"], null, "100000000"])).await;
    let r = exec(&deployer, t["txBytes"].as_str().unwrap()).await;
    let sui_coin = r["objectChanges"].as_array().unwrap().iter()
        .find(|c| c["type"] == "created" && c["objectType"].as_str().unwrap().contains("Coin<0x2::sui::SUI>"))
        .unwrap()["objectId"].as_str().unwrap().to_string();
    call(&deployer, &dep, &pkg, "meta", "deposit", json!(["0x2::sui::SUI"]), json!([acct_sui, sui_coin])).await;
    let r = call(&deployer, &dep, "0x2", "coin", "mint_and_transfer", json!([demo_t]), json!([treasury, "1000000", addr_hex(&dep)])).await;
    let demo_coin = created(&r, "::coin::Coin<");
    call(&deployer, &dep, &pkg, "meta", "deposit", json!([demo_t]), json!([acct_demo, demo_coin])).await;
    assert!(rpc("suix_getCoins", json!([addr_hex(&alice_addr), "0x2::sui::SUI", null, 5])).await["data"].as_array().unwrap().is_empty(),
            "alice has no gas at all");

    // Hai lane từ mnemonic 24 từ.
    let seed = Seed::from_words(MNEMONIC, None).unwrap();
    let signers: Vec<LocalSigner> = [0u32, 1]
        .iter()
        .map(|&i| {
            let (curve, secret) = lane_secret(&seed, "sui", i).unwrap();
            LocalSigner::new(curve, &secret).unwrap()
        })
        .collect();
    for s in &signers {
        faucet(&lane_address(&s.public_key())).await;
    }
    let mut params = toml::Table::new();
    params.insert("package".into(), toml::Value::String(pkg.clone()));
    let cfg = ChainCfg {
        family: "sui".into(),
        network: Some("localnet".into()),
        evm_chain_number: 0,
        rpc_urls: vec![RPC.into()],
        signer_key_env: String::new(),
        private_key: None,
        lanes: vec![0, 1],
        params,
        finality: FinalityCfg { mode: "instant".into(), depth: 0, quorum: 1 },
        dex: None,
        poll_ms: 200,
        stuck_after_secs: 60,
        max_gas_per_tx: 3_000_000,
        max_fee_cap_gwei: 500,
    };
    let adapter = bamboo_node::adapters::build(&cfg, &signers).unwrap();
    assert_eq!(adapter.chain_key(), "sui:localnet");

    let state = Arc::new(Mutex::new(FakeOdoo { tokens: vec![reg_sui.clone(), reg_demo.clone()], ..Default::default() }));
    let odoo = odoo_at(start_fake(state.clone()).await);
    let head0 = adapter.final_head().await.unwrap().unwrap().height;
    state.lock().unwrap().indexed_block = head0;

    // ANTI-LOCK: X (account SUI) ký trước rồi bị giữ; Y (account DEMO) qua lane 1.
    let (x, x_digest) = job(1, &alice, &acct_sui, "0x2::sui::SUI", 1000, 0x11, 0xa1);
    let (y, y_digest) = job(2, &alice, &acct_demo, &demo_t, 500, 0x22, 0xa2);
    assert_eq!(run_job(adapter.as_ref(), &odoo, &state, 1, y).await, ["signed", "broadcast", "mined"]);
    assert_eq!(run_job(adapter.as_ref(), &odoo, &state, 0, x.clone()).await, ["signed", "broadcast", "mined"]);
    // Phát lại X: dry-run từ chối (nonce đã dùng) ⇒ dead, không tốn gas.
    let mut replay = x;
    replay["id"] = json!(3);
    assert_eq!(run_job(adapter.as_ref(), &odoo, &state, 0, replay).await, ["dead"]);
    assert!(state.lock().unwrap().refused.is_empty());

    // Final: index tới khi thấy cả hai thanh toán.
    for _ in 0..60 {
        while index_step(adapter.as_ref(), &odoo).await.unwrap() {}
        if state.lock().unwrap().ingested.iter().filter(|e| e["event"] == "PaymentSettled").count() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let ing = state.lock().unwrap().ingested.clone();
    let shop = addr_hex(&parse_addr(SHOP).unwrap());
    let pay_x = ing.iter().find(|e| e["event"] == "PaymentSettled" && e["contract"] == reg_sui).expect("X settled");
    assert_eq!((pay_x["to"].as_str(), pay_x["amount"].as_str()), (Some(shop.as_str()), Some("1000")));
    assert_eq!(pay_x["entry_ref"], addr_hex(&[0x11u8; 32]));
    assert_eq!(pay_x["from"], addr_hex(&alice_addr));
    let pay_y = ing.iter().find(|e| e["event"] == "PaymentSettled" && e["contract"] == reg_demo).expect("Y settled");
    assert_eq!(pay_y["amount"], "500");
    for d in [x_digest, y_digest] {
        assert!(ing.iter().any(|e| e["event"] == "MetaTransactionExecuted" && e["digest"] == addr_hex(&d)), "digest {}", addr_hex(&d));
    }
    let tx = ing[0]["tx_hash"].as_str().unwrap();
    assert!(tx.len() == 66 && ing[0]["block_hash"].as_str().unwrap().len() == 66);
    let shop_coins = rpc("suix_getAllBalances", json!([shop])).await;
    assert_eq!(shop_coins.as_array().unwrap().len(), 2, "{shop_coins}");
}
