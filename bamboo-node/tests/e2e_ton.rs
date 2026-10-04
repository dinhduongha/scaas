//! cargo test --test e2e_ton -- --ignored --nocapture
//!
//! TON adapter end to end against a TON Center v3 endpoint: by default the sandbox shim
//! (`chains/ton/shim`, real TVM + our compiled contracts, fake blocks; needs `npm ci` + `npx tact` there),
//! or `TON_E2E_API=http://…` for MyLocalTon (then also `TON_E2E_STATE` = JSON like `/shim/state` and a
//! funded faucet — not automated here). Proves: two lanes from a 24-word mnemonic, payments through
//! `lane_step` signed only by the subject (W5R1 lane pays gas), finality through `index_step`, the
//! anti-lock property (X on contract 1 withheld, Y on contract 2 goes through, then X), replay refused.
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Path, State};
use axum::routing::post;
use axum::{Json, Router};
use bamboo_node::adapter::{index_step, lane_step, ChainAdapter};
use bamboo_node::adapters::ton::{
    b64encode, boc_serialize, envelope_hash, Addr, Api, Builder, TonAdapter, W5,
};
use bamboo_node::config::{ChainCfg, FinalityCfg, OdooCfg};
use bamboo_node::keys::{lane_secret, Seed};
use bamboo_node::odoo::Odoo;
use bamboo_node::signer::{Curve, LocalSigner, Signer};
use serde_json::{json, Value};

const ART24: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                     abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
const DOMAIN: &str = "pay.bamboo.example";

struct Shim(Child);
impl Drop for Shim {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

async fn start_shim(port: u16) -> (Option<Shim>, String) {
    if let Ok(url) = std::env::var("TON_E2E_API") {
        return (None, url);
    }
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../chains/ton");
    let ok = Command::new("npx").current_dir(dir).args(["tsc", "-p", "tsconfig.shim.json"]).status().expect("npx in PATH");
    assert!(ok.success(), "shim build failed (run `npm ci && npx tact --config tact.config.json` in chains/ton)");
    let child = Command::new("node")
        .current_dir(dir)
        .args(["build/shim/shim/server.js", "--port", &port.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("node in PATH");
    let url = format!("http://127.0.0.1:{port}");
    let http = reqwest::Client::new();
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if http.get(format!("{url}/shim/state")).send().await.is_ok() {
            break;
        }
    }
    (Some(Shim(child)), url)
}

async fn shim(url: &str, path: &str, body: Value) -> Value {
    let http = reqwest::Client::new();
    let r = if body.is_null() { http.get(format!("{url}{path}")).send().await } else { http.post(format!("{url}{path}")).json(&body).send().await };
    r.unwrap().json().await.unwrap()
}

// ---------------------------------------------------------------- fake Odoo (same rules as e2e.rs)

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
    tokens: Vec<String>,
    states: std::collections::HashMap<i64, String>,
    refused: Vec<Value>,
    jobs: Vec<Value>,
    reports: Vec<Value>,
    ingested: Vec<Value>,
    indexed_block: u64,
}

async fn fake(State(s): State<Arc<Mutex<FakeOdoo>>>, Path((model, method)): Path<(String, String)>, Json(body): Json<Value>) -> Json<Value> {
    let mut o = s.lock().unwrap();
    let out = match (model.as_str(), method.as_str()) {
        // The real masters, raw `0:…` like `blockchain.chain._node_config` (review H1).
        ("blockchain.chain", "node_config") => json!({
            "evm_chain_number": body["evm_chain_number"], "finality_mode": "depth", "finality_depth": 0,
            "finality_quorum": 1, "indexed_block": o.indexed_block, "journal_max_nonce": null, "inflight": [],
            "tokens": o.tokens.iter().map(|a| json!({"address": a, "decimals": 9})).collect::<Vec<_>>()}),
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
            // Like `chain_event._decode`: one event from an unregistered contract rolls the whole batch back.
            if let Some(e) = body["events"].as_array().unwrap().iter().find(|e| !o.tokens.iter().any(|t| e["contract"] == *t)) {
                return Json(json!({"error": format!("Event from an unregistered contract {}", e["contract"])}));
            }
            assert_eq!(body["from_block"].as_u64().unwrap(), o.indexed_block + 1, "cursor gap");
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

// ---------------------------------------------------------------- subject side (what Odoo + the wallet do)

struct Subject {
    key: LocalSigner,
    w5: W5,
    addr: Addr,
}

fn subject(seed: u8, global_id: i32) -> Subject {
    let key = LocalSigner::new(Curve::Ed25519, &[seed; 32]).unwrap();
    let w5 = W5::new(key.public_key().try_into().unwrap(), global_id).unwrap();
    let addr = w5.address().unwrap();
    Subject { key, w5, addr }
}

/// MetaOp v1 pay (Odoo `fam_ton.metaop_cell`) + the connector's signature JSON.
#[allow(clippy::too_many_arguments)]
fn signed_pay(s: &Subject, global_id: i32, contract: &Addr, to: &Addr, amount: u128, lane: [u8; 32], pay_ref: [u8; 32], job: i64) -> Value {
    let valid_until = now() + 600;
    let op = Builder::new()
        .bytes(b"bamboo.metaop.v1")
        .int(global_id as i64, 32)
        .uint(1, 8)
        .uint(amount, 128)
        .uint(0, 64)
        .uint(valid_until as u128, 64)
        .addr(Some(contract))
        .reference(Builder::new().addr(Some(&s.addr)).addr(Some(to)).addr(None).end().unwrap())
        .reference(Builder::new().bytes(&pay_ref).bytes(&lane).bytes(&[0; 32]).end().unwrap())
        .end()
        .unwrap();
    let ts = now();
    let sig = s.key.sign(&envelope_hash(&s.addr, ts, DOMAIN, &op).unwrap()).unwrap();
    let signature = json!({"kind": "ton_connect", "signature": b64encode(&sig), "timestamp": ts, "domain": DOMAIN,
                           "state_init": b64encode(&boc_serialize(&s.w5.state_init().unwrap()))});
    json!({"id": job, "kind": "signed_op", "op": {
        "family": "ton", "contract": contract.raw(), "from": s.addr.raw(), "op_kind": "pay",
        "payload": alloy::hex::encode(boc_serialize(&op)), "signature": signature.to_string(),
        "public_key": null, "auth_kind": "wallet", "digest": format!("0x{}", alloy::hex::encode(op.hash())),
        "valid_until": valid_until, "extra": {}}})
}

async fn wallet_of(api: &Api, master: &Addr, owner: &Addr) -> Addr {
    let owner_cell = Builder::new().addr(Some(owner)).end().unwrap();
    let st = api.run_get(master, "get_wallet_address", vec![json!({"type": "slice", "value": b64encode(&boc_serialize(&owner_cell))})]).await.unwrap();
    let c = bamboo_node::adapters::ton::stack_cell(&st[0]).unwrap();
    c.parser().addr().unwrap().unwrap()
}

async fn balance(api: &Api, master: &Addr, owner: &Addr) -> u128 {
    let w = wallet_of(api, master, owner).await;
    match api.run_get(&w, "get_wallet_data", vec![]).await {
        Ok(st) => bamboo_node::adapters::ton::stack_num(&st[0]).unwrap(),
        Err(_) => 0,
    }
}

#[tokio::test]
#[ignore]
async fn ton_payments_lanes_finality_and_anti_lock() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let (_shim, url) = start_shim(32001).await;
    let st = shim(&url, "/shim/state", Value::Null).await;
    let global_id = st["global_id"].as_i64().unwrap() as i32;
    let (ma, mb) = (Addr::parse(st["masters"]["A"].as_str().unwrap()).unwrap(), Addr::parse(st["masters"]["B"].as_str().unwrap()).unwrap());

    // Two relayer lanes from the 24-word mnemonic (m/44'/607'/i').
    let seed = Seed::from_phrase(ART24.as_bytes(), None).unwrap();
    let signers: Vec<LocalSigner> = (0..2)
        .map(|i| {
            let (c, k) = lane_secret(&seed, "ton", i).unwrap();
            LocalSigner::new(c, &k).unwrap()
        })
        .collect();
    let mut params = toml::Table::new();
    params.insert("global_id".into(), toml::Value::Integer(global_id as i64));
    let cfg = ChainCfg {
        family: "ton".into(),
        network: Some("localnet".into()),
        evm_chain_number: 0,
        rpc_urls: vec![url.clone()],
        signer_key_env: String::new(),
        private_key: None,
        lanes: vec![0, 1],
        params,
        finality: FinalityCfg { mode: "depth".into(), depth: 0, quorum: 1 },
        dex: None,
        poll_ms: 200,
        stuck_after_secs: 60,
        max_gas_per_tx: 0,
        max_fee_cap_gwei: 0,
        ..Default::default()
    };
    let adapter = TonAdapter::new(&cfg, &signers).unwrap();
    assert_eq!(adapter.lanes().len(), 2);
    assert_ne!(adapter.lanes()[0].address, adapter.lanes()[1].address);
    for l in adapter.lanes() {
        shim(&url, "/shim/fund", json!({"address": l.address, "nanoton": "5000000000"})).await;
    }

    let api = Api::new(&url, None).unwrap();
    let alice = subject(1, global_id);
    let shop = subject(2, global_id);
    for m in [&ma, &mb] {
        shim(&url, "/shim/mint", json!({"master": m.raw(), "to": alice.addr.raw(), "amount": "1000"})).await;
    }
    let (wa, wb) = (wallet_of(&api, &ma, &alice.addr).await, wallet_of(&api, &mb, &alice.addr).await);

    // Same lane id on both contracts: lanes/nonces are per contract.
    let lane = [7u8; 32];
    let x = signed_pay(&alice, global_id, &wa, &shop.addr, 400, lane, [0xa1; 32], 1);
    let y = signed_pay(&alice, global_id, &wb, &shop.addr, 250, lane, [0xb2; 32], 2);

    let state = Arc::new(Mutex::new(FakeOdoo { tokens: vec![ma.raw(), mb.raw()], ..Default::default() }));
    let odoo = odoo_at(start_fake(state.clone()).await);

    // Anti-lock: X is withheld (never queued yet); Y goes through on lane 0.
    state.lock().unwrap().jobs.push(y.clone());
    assert!(lane_step(&adapter, &odoo, 0, "e2e#0").await.unwrap());
    assert_eq!(balance(&api, &mb, &shop.addr).await, 250);
    assert_eq!(balance(&api, &ma, &shop.addr).await, 0);
    // Then X goes through, on lane 1.
    state.lock().unwrap().jobs.push(x.clone());
    assert!(lane_step(&adapter, &odoo, 1, "e2e#1").await.unwrap());
    assert_eq!(balance(&api, &ma, &shop.addr).await, 400);
    assert_eq!(balance(&api, &ma, &alice.addr).await, 600);

    let reports = state.lock().unwrap().reports.clone();
    let states: Vec<(&str, i64)> = reports.iter().map(|r| (r["chain_state"].as_str().unwrap(), r["job_id"].as_i64().unwrap())).collect();
    assert_eq!(states, vec![("signed", 2), ("broadcast", 2), ("mined", 2), ("signed", 1), ("broadcast", 1), ("mined", 1)], "{reports:?}");
    assert!(state.lock().unwrap().refused.is_empty());
    assert_eq!(reports[0]["outer_nonce"], 0, "first W5 message deploys the lane wallet (seqno 0)");

    // Replay of Y: the getter simulation sees the lane nonce consumed -> dead, nothing sent.
    let mut replay = y.clone();
    replay["id"] = json!(3);
    state.lock().unwrap().jobs.push(replay);
    assert!(lane_step(&adapter, &odoo, 0, "e2e#0").await.unwrap());
    let last = state.lock().unwrap().reports.last().cloned().unwrap();
    assert_eq!((last["job_id"].as_i64(), last["chain_state"].as_str()), (Some(3), Some("dead")));
    assert!(last["error"].as_str().unwrap().contains("lane nonce"), "{last}");

    // A second payment on lane 0 uses seqno 1 (the lane wallet is deployed now).
    state.lock().unwrap().jobs.push(signed_pay(&alice, global_id, &wb, &shop.addr, 50, [8; 32], [0xc3; 32], 4));
    assert!(lane_step(&adapter, &odoo, 0, "e2e#0").await.unwrap());
    let signed4 = state.lock().unwrap().reports.iter().find(|r| r["job_id"] == 4 && r["chain_state"] == "signed").cloned().unwrap();
    assert_eq!(signed4["outer_nonce"], 1);
    assert_eq!(balance(&api, &mb, &shop.addr).await, 300);

    // A job whose forward TON is above the node default sizes its own lane TON (review L8): it pays.
    let mut fwd = signed_pay(&alice, global_id, &wb, &shop.addr, 20, [9; 32], [0xd4; 32], 5);
    fwd["op"]["extra"] = json!({"forward_nanoton": 300_000_000u64});
    state.lock().unwrap().jobs.push(fwd);
    assert!(lane_step(&adapter, &odoo, 1, "e2e#1").await.unwrap());
    let last = state.lock().unwrap().reports.last().cloned().unwrap();
    assert_eq!((last["job_id"].as_i64(), last["chain_state"].as_str()), (Some(5), Some("mined")), "{last}");
    assert_eq!(balance(&api, &mb, &shop.addr).await, 320);

    // Finality: the indexer walks masterchain blocks and reports authenticated events only.
    while index_step(&adapter, &odoo).await.unwrap() {}
    let ingested = state.lock().unwrap().ingested.clone();
    let digest = |j: &Value| j["op"]["digest"].as_str().unwrap().to_string();
    for (job, master, amount, pay_ref) in [(&x, &ma, "400", [0xa1u8; 32]), (&y, &mb, "250", [0xb2; 32])] {
        let exe = ingested.iter().find(|e| e["event"] == "MetaTransactionExecuted" && e["digest"] == digest(job)).expect("executed");
        assert_eq!(exe["contract"], master.raw());
        assert_eq!(exe["from"], alice.addr.raw());
        let paid = ingested
            .iter()
            .find(|e| e["event"] == "PaymentSettled" && e["entry_ref"] == format!("0x{}", alloy::hex::encode(pay_ref)))
            .expect("paid");
        assert_eq!((paid["contract"].as_str(), paid["to"].as_str(), paid["amount"].as_str()), (Some(master.raw().as_str()), Some(shop.addr.raw().as_str()), Some(amount)));
        for k in ["tx_hash", "block_hash"] {
            let h = paid[k].as_str().unwrap();
            assert!(h.starts_with("0x") && h.len() == 66, "{k}: {h}");
        }
    }
    assert_eq!(ingested.iter().filter(|e| e["event"] == "MetaTransactionExecuted").count(), 4);
    assert_eq!(ingested.iter().filter(|e| e["event"] == "PaymentSettled").count(), 4, "mints carry no payRef: no event");
}
