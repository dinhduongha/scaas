//! cargo test --test e2e_cosmos -- --ignored --nocapture
//!
//! Cần docker + image `cosmwasm/wasmd:v0.61.15` và wasm đã build: `smartcontracts/cosmos/build-wasm.sh` (cần `wasm-opt`).
//! Devnet một node, chain-id `scaas-1`, CometBFT RPC 127.0.0.1:31990, REST 127.0.0.1:31991 (S9).
//! Chứng minh: hai lane dẫn xuất từ mnemonic 24 từ; chủ thể chỉ KÝ (không có tài khoản on-chain);
//! thanh toán qua `lane_step` (mô phỏng → ký → journal → broadcast → mined); payload hết hạn ⇒ `dead`;
//! anti-lock R62 end-to-end (X giữ lại, Y qua, rồi X qua); `index_step` gửi event final đúng digest/entry_ref.
//! Devnet TẮT indexer tx (`indexer = "null"`, như nhiều RPC validator): `mined` phải đến từ quét khối (review M2).
use std::net::SocketAddr;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Path, State};
use axum::routing::post;
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use scaas_node::adapter::{index_step, lane_step, ChainAdapter};
use scaas_node::adapters::cosmos::{account_address, CosmosAdapter};
use scaas_node::config::{ChainCfg, FinalityCfg, OdooCfg};
use scaas_node::keys::{lane_secret, Seed};
use scaas_node::odoo::Odoo;
use scaas_node::signer::{Curve, LocalSigner, Signer};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const NAME: &str = "scaas-s9-wasmd";
const IMAGE: &str = "cosmwasm/wasmd:v0.61.15";
const CHAIN: &str = "scaas-1";
const RPC: &str = "http://127.0.0.1:31990";
const REST: &str = "http://127.0.0.1:31991";
const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
    abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

struct Devnet;
impl Drop for Devnet {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["rm", "-f", NAME]).output();
    }
}

const SETUP: &str = r##"set -e
C=$HOME/.wasmd/config
wasmd init n --chain-id scaas-1 >/dev/null 2>&1
sed -i 's/"stake"/"ustake"/g' $C/genesis.json
wasmd keys add validator --keyring-backend test >/dev/null 2>&1
wasmd keys add deployer --keyring-backend test >/dev/null 2>&1
wasmd genesis add-genesis-account validator 1000000000000ustake --keyring-backend test
wasmd genesis add-genesis-account deployer 1000000000000ustake --keyring-backend test
for a in $LANES; do wasmd genesis add-genesis-account $a 1000000000ustake; done
wasmd genesis gentx validator 250000000ustake --chain-id scaas-1 --keyring-backend test >/dev/null 2>&1
wasmd genesis collect-gentxs >/dev/null 2>&1
sed -i 's/^timeout_commit = .*/timeout_commit = "400ms"/' $C/config.toml
sed -i 's/^indexer = .*/indexer = "null"/' $C/config.toml
sed -i '/^\[api\]/,/^\[/ s/^enable = false/enable = true/' $C/app.toml
sed -i 's#^address = "tcp://localhost:1317"#address = "tcp://0.0.0.0:1317"#' $C/app.toml
sed -i 's/^minimum-gas-prices = .*/minimum-gas-prices = "0ustake"/' $C/app.toml
exec wasmd start --rpc.laddr tcp://0.0.0.0:26657
"##;

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

async fn start(lanes: &[String]) -> Devnet {
    let _ = Command::new("docker").args(["rm", "-f", NAME]).output();
    let wasm = concat!(env!("CARGO_MANIFEST_DIR"), "/../smartcontracts/cosmos/artifacts");
    let st = Command::new("docker")
        .args(["run", "-d", "--rm", "--name", NAME, "-p", "127.0.0.1:31990:26657", "-p", "127.0.0.1:31991:1317"])
        .args(["-v", &format!("{wasm}:/wasm:ro"), "-e", &format!("LANES={}", lanes.join(" "))])
        .args(["--entrypoint", "sh", IMAGE, "-c", SETUP])
        .status()
        .expect("docker");
    assert!(st.success(), "docker run");
    let http = reqwest::Client::new();
    for _ in 0..240 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let ok = async {
            let s: Value = http.get(format!("{RPC}/status")).send().await.ok()?.json().await.ok()?;
            let h: u64 = s["result"]["sync_info"]["latest_block_height"].as_str()?.parse().ok()?;
            http.get(format!("{REST}/cosmos/base/tendermint/v1beta1/node_info")).send().await.ok()?.error_for_status().ok()?;
            (h >= 2).then_some(())
        };
        if ok.await.is_some() {
            return Devnet;
        }
    }
    panic!("wasmd did not start");
}

fn wasmd(args: &[&str]) -> Value {
    let out = Command::new("docker").args(["exec", NAME, "wasmd"]).args(args).args(["-o", "json"]).output().unwrap();
    assert!(out.status.success(), "wasmd {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    serde_json::from_slice(&out.stdout).unwrap_or_else(|_| panic!("json from wasmd {args:?}: {}", String::from_utf8_lossy(&out.stdout)))
}

/// Gửi một tx bằng khoá `deployer` (chỉ CheckTx: không có indexer tx để `q tx`).
fn deployer_tx(args: &[&str]) {
    let mut a = vec!["tx", "wasm"];
    a.extend_from_slice(args);
    a.extend_from_slice(&["--from", "deployer", "--keyring-backend", "test", "--chain-id", CHAIN, "--gas", "auto",
        "--gas-adjustment", "1.5", "-y"]);
    let r = wasmd(&a);
    assert_eq!(r["code"].as_u64(), Some(0), "{r}");
}

/// Chờ tx vào khối bằng truy vấn TRẠNG THÁI: `list` đổi so với `before` ⇒ trả phần tử mới.
async fn wait_new(list: impl Fn() -> Vec<String>, before: &[String]) -> String {
    for _ in 0..60 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if let Some(n) = list().into_iter().find(|x| !before.contains(x)) {
            return n;
        }
    }
    panic!("deployer tx not included");
}

fn strings(v: &Value, key: &str, field: Option<&str>) -> Vec<String> {
    let items = v[key].as_array().cloned().unwrap_or_default();
    items.iter().filter_map(|i| field.map_or(i, |f| &i[f]).as_str().map(str::to_string)).collect()
}

async fn store(file: &str) -> String {
    let codes = || strings(&wasmd(&["q", "wasm", "list-code"]), "code_infos", Some("code_id"));
    let before = codes();
    deployer_tx(&["store", &format!("/wasm/{file}")]);
    wait_new(codes, &before).await
}

async fn instantiate(code: &str, msg: &Value, label: &str) -> String {
    let list = || strings(&wasmd(&["q", "wasm", "list-contract-by-code", code]), "contracts", None);
    let before = list();
    deployer_tx(&["instantiate", code, &msg.to_string(), "--label", label, "--no-admin"]);
    wait_new(list, &before).await
}

async fn balance(token: &str, who: &str) -> u128 {
    let q = B64.encode(json!({"balance": {"address": who}}).to_string());
    let v: Value = reqwest::get(format!("{REST}/cosmwasm/wasm/v1/contract/{token}/smart/{q}")).await.unwrap().json().await.unwrap();
    v["data"]["balance"].as_str().unwrap().parse().unwrap()
}

fn adr036_doc(signer: &str, data: &[u8]) -> Vec<u8> {
    format!(
        r#"{{"account_number":"0","chain_id":"","fee":{{"amount":[],"gas":"0"}},"memo":"","msgs":[{{"type":"sign/MsgSignData","value":{{"data":"{}","signer":"{}"}}}}],"sequence":"0"}}"#,
        B64.encode(data),
        signer
    )
    .into_bytes()
}

struct Subject {
    key: LocalSigner,
    addr: String,
}

impl Subject {
    fn new(seed: u8) -> Self {
        let key = LocalSigner::new(Curve::Secp256k1, &[seed; 32]).unwrap();
        let addr = account_address("wasm", &key.public_key());
        Self { key, addr }
    }

    /// Job `signed_op` đúng như Odoo phát (payload hex, chữ ký base64 64 byte, khoá hex).
    fn job(&self, id: i64, token: &str, to: &str, amount: u128, lane: u8, valid_until: u64) -> (Value, String) {
        let payload = format!(
            r#"{{"amount":"{amount}","contract":"{token}","domain":"scaas.metaop.v1","extra":"","from":"{}","lane":"{}","network":"{CHAIN}","nonce":0,"op":"pay","pay_ref":"{}","relayer":"","to":"{to}","valid_until":{valid_until}}}"#,
            self.addr,
            alloy::hex::encode([lane; 32]),
            alloy::hex::encode([lane ^ 0x5a; 32])
        );
        let sig = self.key.sign(&Sha256::digest(adr036_doc(&self.addr, payload.as_bytes()))).unwrap();
        let digest = format!("0x{}", alloy::hex::encode(Sha256::digest(payload.as_bytes())));
        let job = json!({"id": id, "kind": "signed_op", "op": {
            "family": "cosmos", "contract": token, "from": self.addr, "op_kind": "pay",
            "payload": alloy::hex::encode(payload.as_bytes()), "signature": B64.encode(&sig[..64]),
            "public_key": alloy::hex::encode(self.key.public_key()), "auth_kind": "wallet", "digest": digest,
            "valid_until": valid_until, "extra": {}}});
        (job, digest)
    }
}

// ------------------------------------------------------------------ fake Odoo (như tests/e2e.rs)

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
    /// Token đăng ký ở Odoo, dạng bech32 thật (review H1: node_config phải đọc được chúng).
    tokens: Vec<String>,
}

async fn fake(State(s): State<Arc<Mutex<FakeOdoo>>>, Path((model, method)): Path<(String, String)>, Json(body): Json<Value>) -> Json<Value> {
    let mut o = s.lock().unwrap();
    let out = match (model.as_str(), method.as_str()) {
        ("blockchain.chain", "node_config") => json!({"evm_chain_number": body["evm_chain_number"], "finality_mode": "instant",
            "finality_depth": 0, "finality_quorum": 1, "indexed_block": o.indexed_block,
            "tokens": o.tokens.iter().map(|t| json!({"address": t, "decimals": 6})).collect::<Vec<_>>(),
            "journal_max_nonce": null, "inflight": []}),
        ("blockchain.relay.job", "relay_poll") => {
            assert_eq!(body["evm_chain_number"], "cosmos:scaas-1");
            json!(std::mem::take(&mut o.jobs))
        }
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
            assert_eq!(body["from_block"].as_u64(), Some(o.indexed_block + 1), "cursor gap");
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

fn cfg() -> ChainCfg {
    let mut params = toml::Table::new();
    params.insert("rest".into(), REST.into());
    params.insert("prefix".into(), "wasm".into());
    params.insert("denom".into(), "ustake".into());
    params.insert("gas_price".into(), "0".into());
    params.insert("zero_fee".into(), true.into());
    ChainCfg {
        family: "cosmos".into(),
        network: Some(CHAIN.into()),
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
        max_fee_cap_gwei: 0,
        ..Default::default()
    }
}

fn states(o: &Arc<Mutex<FakeOdoo>>, id: i64) -> Vec<String> {
    let o = o.lock().unwrap();
    o.reports.iter().filter(|r| r["job_id"] == id).map(|r| r["chain_state"].as_str().unwrap().to_string()).collect()
}

#[tokio::test]
#[ignore]
async fn cosmos_payment_lanes_finality_and_anti_lock() {
    let seed = Seed::from_words(MNEMONIC, None).unwrap();
    let signers: Vec<LocalSigner> = (0..2)
        .map(|i| {
            let (c, k) = lane_secret(&seed, "cosmos", i).unwrap();
            LocalSigner::new(c, &k).unwrap()
        })
        .collect();
    let lane_addrs: Vec<String> = signers.iter().map(|s| account_address("wasm", &s.public_key())).collect();
    assert_eq!(lane_addrs[0], "wasm1r5v5srda7xfth3hn2s26txvrcrntldju3hkw75", "same key as the cross vector");
    let _net = start(&lane_addrs).await;

    let alice = Subject::new(7);
    let payee = account_address("wasm", &LocalSigner::new(Curve::Secp256k1, &[8; 32]).unwrap().public_key());
    let code = store("scaas_token.wasm").await;
    for f in ["scaas_mandate.wasm", "scaas_dex.wasm"] {
        store(f).await; // wasmd chấp nhận cả ba wasm (tính năng wasm, kích thước).
    }
    let init = |sym: &str| json!({"name": sym, "symbol": sym, "decimals": 6,
        "initial_balances": [{"address": alice.addr, "amount": "1000000"}]});
    let t1 = instantiate(&code, &init("TOKA"), "t1").await;
    let t2 = instantiate(&code, &init("TOKB"), "t2").await;

    let state = Arc::new(Mutex::new(FakeOdoo { tokens: vec![t1.clone(), t2.clone()], ..Default::default() }));
    let odoo = odoo_at(start_fake(state.clone()).await);
    let adapter = CosmosAdapter::new(&cfg(), signers).unwrap();
    assert_eq!(adapter.lanes()[1].address, lane_addrs[1]);

    // Anti-lock (R62): Alice ký X (token 1) và Y (token 2) cùng lúc; X bị giữ lại.
    let vu = now() + 600;
    let (x, dx) = alice.job(1, &t1, &payee, 111, 1, vu);
    let (y, dy) = alice.job(2, &t2, &payee, 222, 2, vu);
    state.lock().unwrap().jobs.push(y);
    assert!(lane_step(&adapter, &odoo, 0, "n#0").await.unwrap());
    assert_eq!(states(&state, 2), ["signed", "broadcast", "mined"]);
    let y_tx = state.lock().unwrap().reports.iter().find_map(|r| (r["job_id"] == 2).then(|| r["tx_hash"].as_str()).flatten().map(str::to_string)).unwrap();
    let get_tx = reqwest::get(format!("{REST}/cosmos/tx/v1beta1/txs/{}", y_tx.trim_start_matches("0x").to_uppercase())).await.unwrap();
    assert_ne!(get_tx.status().as_u16(), 200, "indexer off: `mined` came from the block scan");
    assert_eq!(balance(&t2, &payee).await, 222);
    assert_eq!(balance(&t1, &payee).await, 0, "X still withheld");
    state.lock().unwrap().jobs.push(x);
    assert!(lane_step(&adapter, &odoo, 1, "n#1").await.unwrap());
    assert_eq!(states(&state, 1), ["signed", "broadcast", "mined"]);
    assert_eq!(balance(&t1, &payee).await, 111);
    assert_eq!(balance(&t1, &alice.addr).await, 1_000_000 - 111);

    // Payload hết hạn: mô phỏng bị contract từ chối ⇒ job chết, không gửi gì.
    let (late, _) = alice.job(3, &t1, &payee, 5, 3, now() - 3600);
    state.lock().unwrap().jobs.push(late);
    assert!(lane_step(&adapter, &odoo, 0, "n#0").await.unwrap());
    assert_eq!(states(&state, 3), ["dead"]);
    let why = state.lock().unwrap().reports.last().unwrap()["error"].as_str().unwrap().to_string();
    assert!(why.contains("expired"), "{why}");
    // Replay của Y: mô phỏng từ chối, nonce đã tiêu ⇒ `consumed` (R80), không `dead`.
    let (y_again, _) = alice.job(4, &t2, &payee, 222, 2, vu);
    state.lock().unwrap().jobs.push(y_again);
    assert!(lane_step(&adapter, &odoo, 1, "n#1").await.unwrap());
    assert_eq!(states(&state, 4), ["consumed"]);

    // Finality: indexer đưa event của vùng đã commit vào Odoo, đúng digest/entry_ref.
    for _ in 0..20 {
        if !index_step(&adapter, &odoo).await.unwrap() {
            break;
        }
    }
    let o = state.lock().unwrap();
    assert!(o.refused.is_empty(), "{:?}", o.refused);
    let digests: Vec<&str> = o.ingested.iter().filter(|e| e["event"] == "MetaTransactionExecuted").filter_map(|e| e["digest"].as_str()).collect();
    assert_eq!(digests, [dy.as_str(), dx.as_str()], "Y then X");
    let pays: Vec<(&str, &str, &str)> = o
        .ingested
        .iter()
        .filter(|e| e["event"] == "PaymentSettled")
        .map(|e| (e["contract"].as_str().unwrap(), e["amount"].as_str().unwrap(), e["entry_ref"].as_str().unwrap()))
        .collect();
    let r = |l: u8| format!("0x{}", alloy::hex::encode([l ^ 0x5a; 32]));
    assert_eq!(pays, [(t2.as_str(), "222", r(2).as_str()), (t1.as_str(), "111", r(1).as_str())]);
    for e in &o.ingested {
        assert_eq!(e["from"].as_str(), Some(alice.addr.as_str()));
        assert!(e["block_hash"].as_str().unwrap().len() == 66 && e["tx_hash"].as_str().unwrap().starts_with("0x"));
    }
}
