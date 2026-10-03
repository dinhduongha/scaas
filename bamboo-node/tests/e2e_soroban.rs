//! cargo test --test e2e_soroban -- --ignored --nocapture
//!
//! Cần `stellar/quickstart` (local, core+rpc+horizon/friendbot) tại `$STELLAR_URL` (mặc định
//! `http://127.0.0.1:31980`), CLI `stellar` ≥ 23 tại `$STELLAR_BIN`, và target `wasm32v1-none`.
//! Chứng minh trên ledger thật với contract thật (R65, R62):
//! 1. hai lane từ mnemonic 24 từ; chủ thể là ví seed `m/44'/148'/9'` (R32) chỉ KÝ auth entry, không gửi tx;
//! 2. anti-lock: X (token 1) bị giữ, Y (token 2) qua `lane_step` thành công, rồi X thành công;
//! 3. phát lại X ⇒ mô phỏng từ chối (nonce đã dùng) ⇒ job chết, không tốn phí;
//! 4. fee-bump: lane 0 trả phí cho tx của lane 1;
//! 5. `index_step` đưa `PaymentSettled` + `MetaTransactionExecuted` (digest khớp) về Odoo giả.
use std::net::SocketAddr;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Path, State};
use axum::routing::post;
use axum::{Json, Router};
use bamboo_node::adapter::{index_step, lane_step, ChainAdapter};
use bamboo_node::adapters::soroban::{network_id, SorobanAdapter};
use bamboo_node::config::{ChainCfg, FinalityCfg, OdooCfg};
use bamboo_node::keys::{lane_secret, Seed};
use bamboo_node::odoo::Odoo;
use bamboo_node::signer::{base32, crc16_xmodem, stellar_account_strkey, LocalSigner, Signer};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use stellar_xdr::{
    Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization, Int128Parts, InvokeContractArgs, Limits, ScAddress,
    ScSymbol, ScVal, SorobanAuthorizedFunction, SorobanAuthorizedInvocation, WriteXdr,
};

const NETWORK: &str = "Standalone Network ; February 2017";
const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
    abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

fn url() -> String {
    std::env::var("STELLAR_URL").unwrap_or_else(|_| "http://127.0.0.1:31980".into())
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

fn key(i: u32) -> LocalSigner {
    let seed = Seed::from_words(MNEMONIC, None).unwrap();
    let (curve, k) = lane_secret(&seed, "soroban", i).unwrap();
    LocalSigner::new(curve, &k).unwrap()
}

fn g(s: &LocalSigner) -> String {
    stellar_account_strkey(&s.public_key())
}

/// `S…` strkey (seed ed25519) cho CLI.
fn secret(i: u32) -> String {
    let seed = Seed::from_words(MNEMONIC, None).unwrap();
    let (_, k) = lane_secret(&seed, "soroban", i).unwrap();
    let mut p = vec![18u8 << 3];
    p.extend_from_slice(&k[..]);
    let crc = crc16_xmodem(&p);
    p.extend_from_slice(&crc.to_le_bytes());
    base32(&p)
}

async fn rpc(method: &str, params: Value) -> Value {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    let r: Value = reqwest::Client::new().post(format!("{}/rpc", url())).json(&body).send().await.unwrap().json().await.unwrap();
    assert!(r.get("error").is_none(), "{method}: {r}");
    r["result"].clone()
}

async fn fund(addr: &str) {
    let r = reqwest::get(format!("{}/friendbot?addr={addr}", url())).await.unwrap();
    let st = r.status();
    let body = r.text().await.unwrap();
    assert!(st.is_success() || body.contains("createAccountAlreadyExist"), "friendbot {addr}: {body}");
}

fn cli(args: &[&str]) -> String {
    let bin = std::env::var("STELLAR_BIN").unwrap_or_else(|_| "stellar".into());
    let rpc = format!("{}/rpc", url());
    let mut full = args.to_vec();
    let pos = full.iter().position(|a| *a == "--").unwrap_or(full.len());
    let net = ["--rpc-url", rpc.as_str(), "--network-passphrase", NETWORK];
    full.splice(pos..pos, net);
    let out = Command::new(&bin).args(&full).output().expect("stellar CLI");
    assert!(out.status.success(), "stellar {}: {}", full.join(" "), String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

fn wasm(name: &str) -> String {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../chains/soroban");
    let st = Command::new("cargo")
        .current_dir(dir)
        .args(["build", "--target", "wasm32v1-none", "--release", "-p", &format!("bamboo-{name}")])
        .status()
        .unwrap();
    assert!(st.success());
    format!("{dir}/target/wasm32v1-none/release/bamboo_{name}.wasm")
}

fn deploy_token(admin_secret: &str, admin: &str) -> String {
    let w = wasm("token");
    cli(&["contract", "deploy", "--wasm", &w, "--source-account", admin_secret, "--",
          "--admin", admin, "--decimals", "7", "--name", "Bamboo", "--symbol", "BMB"])
}

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
}

async fn fake(State(s): State<Arc<Mutex<FakeOdoo>>>, Path((model, method)): Path<(String, String)>, Json(body): Json<Value>) -> Json<Value> {
    let mut o = s.lock().unwrap();
    let out = match (model.as_str(), method.as_str()) {
        // Token list empty: the Soroban adapter watches `params.contracts` (TokenCfg is EVM-typed — see report).
        ("blockchain.chain", "node_config") => json!({
            "evm_chain_number": body["evm_chain_number"], "finality_mode": "instant", "finality_depth": 0,
            "finality_quorum": 1, "indexed_block": o.indexed_block, "tokens": [], "journal_max_nonce": null, "inflight": []}),
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

fn chain_cfg(contracts: &[&str], fee_bump: bool) -> ChainCfg {
    let mut params = toml::Table::new();
    params.insert("network_passphrase".into(), NETWORK.into());
    params.insert("contracts".into(), toml::Value::Array(contracts.iter().map(|c| toml::Value::from(*c)).collect()));
    if fee_bump {
        params.insert("fee_bump_lane".into(), 0.into());
    }
    ChainCfg {
        family: "soroban".into(),
        network: Some("standalone".into()),
        evm_chain_number: 0,
        rpc_urls: vec![format!("{}/rpc", url())],
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
    }
}

fn addr(s: &str) -> ScVal {
    ScVal::Address(s.parse::<ScAddress>().unwrap())
}

/// Đúng phép dựng của Odoo `fam_soroban.build_terms` (vector chéo ghim ở ba phía).
struct Signed {
    job: Value,
    digest: String,
}

fn sign_pay(subject: &LocalSigner, token: &str, to: &str, amount: i128, pay_ref: [u8; 32], nonce: i64, exp: u32, id: i64) -> Signed {
    let from = g(subject);
    let valid_until = now() + 600;
    let args = vec![
        addr(&from),
        addr(to),
        ScVal::I128(Int128Parts { hi: (amount >> 64) as i64, lo: amount as u64 }),
        ScVal::Bytes(pay_ref.to_vec().try_into().unwrap()),
        ScVal::U64(valid_until),
    ];
    let call = InvokeContractArgs {
        contract_address: token.parse().unwrap(),
        function_name: ScSymbol("pay".try_into().unwrap()),
        args: args.clone().try_into().unwrap(),
    };
    let pre = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: Hash(network_id(NETWORK)),
        nonce,
        signature_expiration_ledger: exp,
        invocation: SorobanAuthorizedInvocation { function: SorobanAuthorizedFunction::ContractFn(call), sub_invocations: Default::default() },
    })
    .to_xdr(Limits::none())
    .unwrap();
    let sig = subject.sign(&Sha256::digest(&pre)).unwrap();
    let dv = ScVal::Vec(Some(
        vec![
            ScVal::Symbol(ScSymbol("bamboo_metaop_v1".try_into().unwrap())),
            ScVal::Bytes(network_id(NETWORK).to_vec().try_into().unwrap()),
            addr(token),
            ScVal::Symbol(ScSymbol("pay".try_into().unwrap())),
            ScVal::Vec(Some(args.try_into().unwrap())),
        ]
        .try_into()
        .unwrap(),
    ));
    let digest = format!("0x{}", alloy::hex::encode(Sha256::digest(dv.to_xdr(Limits::none()).unwrap())));
    let job = json!({"id": id, "kind": "signed_op", "op": {
        "family": "soroban", "contract": token, "from": from, "op_kind": "pay",
        "payload": alloy::hex::encode(&pre), "signature": alloy::hex::encode(&sig), "public_key": from,
        "auth_kind": "seed", "digest": digest, "valid_until": valid_until, "extra": {}}});
    Signed { job, digest }
}

fn last_state(o: &FakeOdoo, id: i64) -> String {
    o.states.get(&id).cloned().unwrap_or_default()
}

fn report_of(o: &FakeOdoo, id: i64, state: &str) -> Value {
    o.reports.iter().rev().find(|r| r["job_id"] == id && r["chain_state"] == state).cloned().unwrap_or_default()
}

#[tokio::test]
#[ignore]
async fn soroban_payments_anti_lock_fee_bump_and_finality() {
    let (lane0, lane1, deployer, payee, subject) = (key(0), key(1), key(7), key(8), key(9));
    for k in [&lane0, &lane1, &deployer, &subject] {
        fund(&g(k)).await;
    }
    let (t1, t2) = (deploy_token(&secret(7), &g(&deployer)), deploy_token(&secret(7), &g(&deployer)));
    for t in [&t1, &t2] {
        cli(&["contract", "invoke", "--id", t, "--source-account", &secret(7), "--", "mint", "--to", &g(&subject), "--amount", "1000000"]);
    }

    let state = Arc::new(Mutex::new(FakeOdoo::default()));
    let start = rpc("getLatestLedger", json!({})).await["sequence"].as_u64().unwrap();
    state.lock().unwrap().indexed_block = start - 1;
    let odoo = odoo_at(start_fake(state.clone()).await);
    let signers = [key(0), key(1)];
    let adapter = SorobanAdapter::new(&chain_cfg(&[&t1, &t2], false), &signers).unwrap();
    assert_eq!(adapter.lanes()[1].address, g(&lane1));
    let seq0 = adapter.sequence(0).await.unwrap();

    let exp = start as u32 + 1000;
    let x = sign_pay(&subject, &t1, &g(&payee), 1_000, [0xA1; 32], 0x1111_2222, exp, 1);
    let y = sign_pay(&subject, &t2, &g(&payee), 2_000, [0xB2; 32], -0x3333_4444, exp, 2);

    // Anti-lock (R62): X is withheld; Y on the other contract goes through lane 1.
    state.lock().unwrap().jobs.push(y.job.clone());
    assert!(lane_step(&adapter, &odoo, 1, "n#1").await.unwrap());
    assert_eq!(last_state(&state.lock().unwrap(), 2), "mined", "{:?}", state.lock().unwrap().reports);
    // Then X lands, on lane 0.
    state.lock().unwrap().jobs.push(x.job.clone());
    assert!(lane_step(&adapter, &odoo, 0, "n#0").await.unwrap());
    assert_eq!(last_state(&state.lock().unwrap(), 1), "mined", "{:?}", state.lock().unwrap().reports);
    assert_eq!(report_of(&state.lock().unwrap(), 1, "signed")["signer_address"], json!(g(&lane0)));
    assert_eq!(adapter.sequence(0).await.unwrap(), seq0 + 1, "the lane's own sequence advanced; the subject sent nothing");

    // Replaying X: the host refuses the spent (address, nonce) at simulation — dead, no fee spent.
    let mut replay = x.job.clone();
    replay["id"] = json!(3);
    state.lock().unwrap().jobs.push(replay);
    assert!(lane_step(&adapter, &odoo, 0, "n#0").await.unwrap());
    assert_eq!(last_state(&state.lock().unwrap(), 3), "dead");
    assert_eq!(adapter.sequence(0).await.unwrap(), seq0 + 1);

    // Fee-bump: lane 0 pays for lane 1's tx.
    let bumped = SorobanAdapter::new(&chain_cfg(&[&t1, &t2], true), &signers).unwrap();
    let z = sign_pay(&subject, &t1, &g(&payee), 3_000, [0xC3; 32], 77, exp, 4);
    state.lock().unwrap().jobs.push(z.job.clone());
    assert!(lane_step(&bumped, &odoo, 1, "n#1").await.unwrap());
    assert_eq!(last_state(&state.lock().unwrap(), 4), "mined", "{:?}", state.lock().unwrap().reports);

    // Finality: index up to the head; the indexed events carry the digests the subject signed for.
    let mined: u64 = rpc("getLatestLedger", json!({})).await["sequence"].as_u64().unwrap();
    for _ in 0..60 {
        let _ = index_step(&adapter, &odoo).await.unwrap();
        if state.lock().unwrap().indexed_block >= mined {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let o = state.lock().unwrap();
    assert!(o.indexed_block >= mined);
    assert!(o.refused.is_empty(), "{:?}", o.refused);
    let paid: Vec<_> = o.ingested.iter().filter(|e| e["event"] == "PaymentSettled").collect();
    let executed: Vec<_> = o.ingested.iter().filter(|e| e["event"] == "MetaTransactionExecuted").collect();
    assert_eq!(paid.len(), 3, "{:?}", o.ingested);
    let refs: Vec<_> = paid.iter().map(|e| e["entry_ref"].as_str().unwrap().to_string()).collect();
    for r in ["a1", "b2", "c3"] {
        assert!(refs.contains(&format!("0x{}", r.repeat(32))), "{refs:?}");
    }
    let digests: Vec<_> = executed.iter().map(|e| e["digest"].as_str().unwrap().to_string()).collect();
    for d in [&x.digest, &y.digest, &z.digest] {
        assert!(digests.contains(d), "{digests:?}");
    }
    for e in o.ingested.iter() {
        assert_eq!(e["from"], json!(g(&subject)));
        assert!(e["block_hash"].as_str().unwrap().len() == 66 && e["tx_hash"].as_str().unwrap().starts_with("0x"));
    }
    let y_tx = report_of(&o, 2, "signed")["tx_hash"].clone();
    assert!(paid.iter().any(|e| e["tx_hash"] == y_tx && e["amount"] == "2000" && e["contract"] == json!(t2)));
}
