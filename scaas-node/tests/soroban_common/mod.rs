//! Shared by `e2e_soroban` and `e2e_soroban_ua`: the network (env), keys, the stellar CLI, deploys and the fake Odoo.
//!
//! Env (local quickstart defaults; T14 points them at the Stellar testnet):
//! - `STELLAR_URL` — the RPC endpoint (default `http://127.0.0.1:31980/rpc`, `quickstart.sh`);
//! - `STELLAR_PASSPHRASE` — the network passphrase (default `Standalone Network ; February 2017`);
//! - `STELLAR_FRIENDBOT` — the friendbot (default `http://127.0.0.1:31980/friendbot`);
//! - `STELLAR_BIN` — the stellar CLI ≥ 30 (default `stellar`).
#![allow(dead_code)]
use std::net::SocketAddr;
use std::process::Command;
use std::sync::{Arc, Mutex};

use axum::extract::{Path, State};
use axum::routing::post;
use axum::{Json, Router};
use scaas_node::adapters::soroban::network_id;
use scaas_node::config::{ChainCfg, FinalityCfg, OdooCfg};
use scaas_node::keys::{lane_secret, Seed};
use scaas_node::odoo::Odoo;
use scaas_node::signer::{base32, crc16_xmodem, stellar_account_strkey, LocalSigner, Signer};
use serde_json::{json, Value};
use stellar_xdr::{Limits, ReadXdr, ScAddress, ScVal, TransactionEnvelope, TransactionExt, TransactionResult};

pub const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
    abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

fn env_or(k: &str, d: &str) -> String {
    std::env::var(k).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| d.into())
}

pub fn rpc_url() -> String {
    env_or("STELLAR_URL", "http://127.0.0.1:31980/rpc")
}

pub fn passphrase() -> String {
    env_or("STELLAR_PASSPHRASE", "Standalone Network ; February 2017")
}

pub fn friendbot() -> String {
    env_or("STELLAR_FRIENDBOT", "http://127.0.0.1:31980/friendbot")
}

pub fn stellar_bin() -> String {
    env_or("STELLAR_BIN", "stellar")
}

pub fn network() -> [u8; 32] {
    network_id(&passphrase())
}

pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

pub fn key(i: u32) -> LocalSigner {
    let seed = Seed::from_words(MNEMONIC, None).unwrap();
    let (curve, k) = lane_secret(&seed, "soroban", i).unwrap();
    LocalSigner::new(curve, &k).unwrap()
}

pub fn g(s: &LocalSigner) -> String {
    stellar_account_strkey(&s.public_key())
}

/// `S…` strkey (seed ed25519) cho CLI.
pub fn secret(i: u32) -> String {
    let seed = Seed::from_words(MNEMONIC, None).unwrap();
    let (_, k) = lane_secret(&seed, "soroban", i).unwrap();
    let mut p = vec![18u8 << 3];
    p.extend_from_slice(&k[..]);
    let crc = crc16_xmodem(&p);
    p.extend_from_slice(&crc.to_le_bytes());
    base32(&p)
}

pub async fn rpc(method: &str, params: Value) -> Value {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    let r: Value = reqwest::Client::new().post(rpc_url()).json(&body).send().await.unwrap().json().await.unwrap();
    assert!(r.get("error").is_none(), "{method}: {r}");
    r["result"].clone()
}

pub async fn latest_ledger() -> u64 {
    rpc("getLatestLedger", json!({})).await["sequence"].as_u64().unwrap()
}

pub async fn fund(addr: &str) {
    let r = reqwest::get(format!("{}?addr={addr}", friendbot())).await.unwrap();
    let st = r.status();
    let body = r.text().await.unwrap();
    assert!(st.is_success() || body.contains("createAccountAlreadyExist") || body.contains("already funded"), "friendbot {addr}: {body}");
}

/// The network options, inserted before `--` (the contract's own arguments follow it).
fn with_net(args: &[&str]) -> Vec<String> {
    let mut full: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let pos = full.iter().position(|a| a == "--").unwrap_or(full.len());
    let net = ["--rpc-url".to_string(), rpc_url(), "--network-passphrase".into(), passphrase()];
    full.splice(pos..pos, net);
    full
}

/// `stellar <args>` with the network options: `(success, stdout, stderr)`.
pub fn cli_raw(args: &[&str]) -> (bool, String, String) {
    let full = with_net(args);
    let out = Command::new(stellar_bin()).args(&full).output().expect("stellar CLI");
    (out.status.success(), String::from_utf8_lossy(&out.stdout).trim().to_string(), String::from_utf8_lossy(&out.stderr).into_owned())
}

pub fn cli(args: &[&str]) -> String {
    let (ok, out, err) = cli_raw(args);
    assert!(ok, "stellar {}: {err}", with_net(args).join(" "));
    out
}

/// A state-changing `stellar contract invoke`: its output and the transaction hash the CLI reports (`-v` logs it).
pub fn cli_tx(args: &[&str]) -> (String, String) {
    let args = [&["-v"], args].concat();
    let (ok, out, err) = cli_raw(&args);
    assert!(ok, "stellar {}: {err}", with_net(&args).join(" "));
    let hash = tx_hash_in(&err).unwrap_or_else(|| panic!("no transaction hash in the CLI output: {err}"));
    (out, hash)
}

/// The first 64-hex word after `Signing transaction:` in the CLI's `-v` log (stellar-cli 30 prints no hash otherwise).
pub fn tx_hash_in(log: &str) -> Option<String> {
    let at = log.find("Signing transaction")?;
    log[at..].split(|c: char| !c.is_ascii_hexdigit()).find(|w| w.len() == 64).map(str::to_lowercase)
}

pub fn wasm(name: &str) -> String {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../smartcontracts/soroban");
    // soroban-sdk 30 refuses a plain `cargo build` for wasm: stellar-cli >= 30 builds the contract
    let st = Command::new(stellar_bin())
        .current_dir(dir)
        .args(["contract", "build", "--package", &format!("scaas-{name}")])
        .status()
        .unwrap();
    assert!(st.success());
    format!("{dir}/target/wasm32v1-none/release/scaas_{name}.wasm")
}

/// The token's `registry: Option<Address>` is passed only when set (omitted = `None`, the UA ledger off).
pub fn deploy_token(admin_secret: &str, admin: &str, registry: Option<&str>) -> String {
    let w = wasm("token");
    let mut args = vec!["contract", "deploy", "--wasm", &w, "--source-account", admin_secret, "--",
                        "--admin", admin, "--decimals", "7", "--name", "SCaaS", "--symbol", "BMB"];
    // an `Option<Address>` argument is JSON: the quoted strkey
    let r = registry.map(|r| format!("\"{r}\""));
    if let Some(r) = &r {
        args.extend(["--registry", r]);
    }
    cli(&args)
}

/// `smartcontracts/scripts/deploy.sh soroban local <contract> <tx options…> [-- <constructor args…>]` (the Wasm built
/// by `build.sh soroban`); the network is given by `--rpc-url` / `--network-passphrase`, which override the name.
/// Prints and returns the contract id (`relay_fee`: the router's).
pub fn deploy_sh(contract: &str, source_secret: &str, ctor: &[&str]) -> String {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/../smartcontracts/scripts/deploy.sh");
    let (rpc, pass) = (rpc_url(), passphrase());
    let mut args = vec!["soroban", "local", contract, "--source-account", source_secret, "--rpc-url", &rpc, "--network-passphrase", &pass];
    if !ctor.is_empty() {
        args.push("--");
        args.extend_from_slice(ctor);
    }
    let out = Command::new(script).env("STELLAR_BIN", stellar_bin()).args(&args).output().expect("deploy.sh");
    assert!(out.status.success(), "deploy.sh soroban {contract}: {}", String::from_utf8_lossy(&out.stderr));
    let id = String::from_utf8(out.stdout).unwrap().trim().lines().last().unwrap_or_default().to_string();
    assert!(id.starts_with('C') && id.len() == 56, "deploy.sh soroban {contract}: no contract id in {id:?}");
    println!("deploy.sh soroban local {contract}: {id}");
    id
}

/// What a transaction cost: its ledger, the declared CPU instructions (the simulation's, set in the transaction data)
/// and the fee charged (stroops).
pub struct Cost {
    pub ledger: u64,
    pub instructions: u32,
    pub resource_fee: i64,
    pub fee_charged: i64,
}

pub async fn cost(hash: &str) -> Cost {
    let hash = hash.trim_start_matches("0x");
    let mut r = Value::Null;
    for _ in 0..30 {
        r = rpc("getTransaction", json!({"hash": hash})).await;
        if r["status"] != "NOT_FOUND" {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    assert_eq!(r["status"], "SUCCESS", "{hash}: {r}");
    let env = TransactionEnvelope::from_xdr_base64(r["envelopeXdr"].as_str().unwrap(), Limits::none()).unwrap();
    let tx = match env {
        TransactionEnvelope::Tx(e) => e.tx,
        TransactionEnvelope::TxFeeBump(e) => match e.tx.inner_tx {
            stellar_xdr::FeeBumpTransactionInnerTx::Tx(i) => i.tx,
        },
        TransactionEnvelope::TxV0(_) => panic!("{hash}: a v0 envelope"),
    };
    let TransactionExt::V1(data) = tx.ext else { panic!("{hash}: no Soroban transaction data") };
    let res = TransactionResult::from_xdr_base64(r["resultXdr"].as_str().unwrap(), Limits::none()).unwrap();
    Cost { ledger: r["ledger"].as_u64().unwrap(), instructions: data.resources.instructions, resource_fee: data.resource_fee, fee_charged: res.fee_charged }
}

/// One log line per transaction: `T10 <what>: tx <hash> ledger <n> cpu_insns <n> resource_fee <n> fee_charged <n>`.
pub async fn log_cost(what: &str, hash: &str) -> Cost {
    let c = cost(hash).await;
    println!(
        "T10 {what}: tx {} ledger {} cpu_insns {} resource_fee {} fee_charged {} stroops",
        hash.trim_start_matches("0x"), c.ledger, c.instructions, c.resource_fee, c.fee_charged
    );
    c
}

pub fn allowed(from: &str, to: &str) -> bool {
    matches!(
        (from, to),
        ("queued", "nonce_leased")
            | ("nonce_leased", "queued" | "signed" | "dead" | "consumed")
            | ("signed", "broadcast" | "mined" | "reverted" | "queued" | "dead")
            | ("broadcast", "mined" | "reverted" | "broadcast" | "queued" | "dead")
            | ("mined", "reverted")
    )
}

#[derive(Default)]
pub struct FakeOdoo {
    pub states: std::collections::HashMap<i64, String>,
    pub refused: Vec<Value>,
    pub jobs: Vec<Value>,
    pub reports: Vec<Value>,
    pub ingested: Vec<Value>,
    pub indexed_block: u64,
    /// Token contract ids registered in Odoo (strkey `C…`) — the indexer must filter on these.
    pub tokens: Vec<String>,
    /// Other contracts whose events Odoo accepts (the relay-fee router's `RelayFeePaid`).
    pub others: Vec<String>,
}

async fn fake(State(s): State<Arc<Mutex<FakeOdoo>>>, Path((model, method)): Path<(String, String)>, Json(body): Json<Value>) -> Json<Value> {
    let mut o = s.lock().unwrap();
    let out = match (model.as_str(), method.as_str()) {
        ("blockchain.chain", "node_config") => json!({
            "evm_chain_number": body["evm_chain_number"], "finality_mode": "instant", "finality_depth": 0,
            "finality_quorum": 1, "indexed_block": o.indexed_block,
            "tokens": o.tokens.iter().map(|t| json!({"address": t, "decimals": 7})).collect::<Vec<_>>(), "journal_max_nonce": null, "inflight": []}),
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
            assert_eq!(body["from_block"].as_u64().unwrap(), o.indexed_block + 1, "cursor gap");
            o.indexed_block = body["to_block"].as_u64().unwrap();
            // Real ingest rejects events of contracts Odoo has not registered.
            for e in body["events"].as_array().unwrap() {
                assert!(o.tokens.iter().chain(&o.others).any(|t| e["contract"] == json!(t)), "event from unregistered contract: {e}");
            }
            o.ingested.extend(body["events"].as_array().unwrap().iter().cloned());
            json!({"indexed_block": o.indexed_block, "created": 0})
        }
        _ => json!({"error": "unexpected"}),
    };
    Json(out)
}

pub async fn start_fake(state: Arc<Mutex<FakeOdoo>>) -> SocketAddr {
    let app = Router::new().route("/json/2/{model}/{method}", post(fake)).with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

pub fn odoo_at(addr: SocketAddr) -> Odoo {
    let cfg = OdooCfg { url: format!("http://{addr}"), database: "t".into(), relay_api_key_env: String::new(), indexer_api_key_env: String::new() };
    Odoo::with_key(&cfg, "k".into()).unwrap()
}

pub fn chain_cfg(fee_bump: bool) -> ChainCfg {
    let mut params = toml::Table::new();
    params.insert("network_passphrase".into(), passphrase().into());
    if fee_bump {
        params.insert("fee_bump_lane".into(), 0.into());
    }
    ChainCfg {
        family: "soroban".into(),
        network: Some("standalone".into()),
        evm_chain_number: 0,
        rpc_urls: vec![rpc_url()],
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
        ..Default::default()
    }
}

pub fn addr(s: &str) -> ScVal {
    ScVal::Address(s.parse::<ScAddress>().unwrap())
}

pub fn last_state(o: &FakeOdoo, id: i64) -> String {
    o.states.get(&id).cloned().unwrap_or_default()
}

pub fn report_of(o: &FakeOdoo, id: i64, state: &str) -> Value {
    o.reports.iter().rev().find(|r| r["job_id"] == id && r["chain_state"] == state).cloned().unwrap_or_default()
}
