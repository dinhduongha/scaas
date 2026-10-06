//! cargo test --test e2e_solana -- --ignored --nocapture
//!
//! Cần `solana-test-validator` của luồng S12 đang chạy với program nạp ở genesis:
//! `smartcontracts/solana/scripts/devnet.sh up --upgradeable-program BDo6exf1vzqX44BJc1WDf4Pw6sGZcxqmuVmQPfgUgS3d
//! target/deploy/scaas.so 73VoVWyfxmaWC6gUjsse6xzNTLLoEhazMCcKakXWbebm --bpf-program
//! A4PasPZEK899MesXpT3MSA4ufnpHcyfxjKuxRXmcZnRJ target/deploy/cpi_wrapper.so` (RPC 32020; program id = id test của
//! localnet, authority = `signer("e2e-upgrade-authority")` — không khoá nào nằm trong repo, review M3; `cpi_wrapper` =
//! program test bọc `relay_pay` trong CPI, review I1). Chứng minh:
//! 1. hai lane relayer từ mnemonic 24 từ (`m/44'/501'/i'/0'`), airdrop; mỗi lane tự tạo durable nonce account (địa
//!    chỉ nonce của lane 1 bị gửi lamports trước — vẫn tạo được, review M1);
//!    alice (chủ thể) không có SOL, tiền nằm ở ATA của Account PDA của nó (mở lười ở lần trả đầu);
//! 2. `initialize` với genesis hash thật; mint SPL Token + mint Token-2022; Odoo giả trả mint thật và TỪ CHỐI event
//!    của mint chưa đăng ký;
//! 3. ANTI-LOCK đồng thời: X `signed` trên lane 0 nhưng bị GIỮ; Y (Token-2022) đi hết tới `mined` trên lane 1; rồi X
//!    qua; phát lại X ⇒ mô phỏng từ chối ⇒ `dead`; chữ ký tự tính = chữ ký RPC; phí = 2 chữ ký;
//! 4. `Rejected`: bytes ký với giá trị nonce đã advance bị preflight từ chối;
//! 5. khởi động lại: job `broadcast` trước crash ⇒ `recover_lane` chốt `mined`; job `signed` chưa gửi ⇒ nonce lane
//!    được advance ⇒ `queued` ngay (không giữ lane tới hạn payload);
//! 6. `index_step` (`finalized`, `getSignaturesForAddress` + `getTransaction`) báo `PaymentSettled` +
//!    `MetaTransactionExecuted` (digest = digest đã ký); mint chưa đăng ký bị bỏ; danh sách token rỗng ⇒ con trỏ đứng
//!    yên.
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::extract::{Path, State};
use axum::routing::post;
use axum::{Json, Router};
use scaas_node::adapter::{index_step, lane_step, recover_lane, Built, ChainAdapter, Family, Head, Lane, Rejected, Signed, TxStatus};
use scaas_node::adapters::solana::{
    account_of, ata, auth_ix, b58, discriminator, find_pda, key, message_v1, nonce_account, parse_auth, relay_pay_ix, Budget, Ix, Key,
    Meta, MetaOp, Pay,
    ATA_PROGRAM, SYSTEM, TOKEN_2022, TOKEN_PROGRAM,
};
use scaas_node::chain::SimError;
use scaas_node::config::{ChainCfg, FinalityCfg, OdooCfg};
use scaas_node::keys::{lane_secret, Seed};
use scaas_node::odoo::{Job, Odoo};
use scaas_node::signer::{Curve, LocalSigner, Signer};
use serde_json::{json, Value};

const RPC: &str = "http://127.0.0.1:32020";
const PROGRAM: &str = "BDo6exf1vzqX44BJc1WDf4Pw6sGZcxqmuVmQPfgUgS3d";
/// `smartcontracts/solana/programs/cpi_wrapper` (test only).
const WRAPPER: &str = "A4PasPZEK899MesXpT3MSA4ufnpHcyfxjKuxRXmcZnRJ";
const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    parts.iter().for_each(|p| h.update(p));
    h.finalize().into()
}

async fn rpc(method: &str, params: Value) -> Value {
    let v: Value = reqwest::Client::new()
        .post(RPC)
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(v.get("error").is_none(), "{method}: {v}");
    v["result"].clone()
}

fn meta(key: Key, signer: bool, writable: bool) -> Meta {
    Meta { key, signer, writable }
}

/// Tx native (dựng môi trường — KHÔNG phải đường relayer): v1, lifetime = blockhash gần nhất, ký bởi mọi signer.
async fn send(ixs: Vec<Ix>, signers: &[&LocalSigner]) -> String {
    let payer: Key = signers[0].public_key().try_into().unwrap();
    let bh = rpc("getLatestBlockhash", json!([{"commitment": "confirmed"}])).await;
    let bh = key(bh["value"]["blockhash"].as_str().unwrap()).unwrap();
    let budget = Budget { priority_lamports: 0, cu: 400_000, loaded_bytes: 4 * 1024 * 1024 };
    let (msg, n) = message_v1(&payer, &bh, &ixs, &budget).unwrap();
    let mut tx = msg.clone();
    for i in 0..n {
        let k = &msg[42 + 32 * i..74 + 32 * i];
        let s = signers.iter().find(|s| s.public_key() == k).expect("missing signer");
        tx.extend_from_slice(&s.sign(&msg).unwrap());
    }
    let b64 = base64_encode(&tx);
    let sig = rpc("sendTransaction", json!([b64, {"encoding": "base64", "preflightCommitment": "confirmed"}])).await;
    let sig = sig.as_str().unwrap().to_string();
    for _ in 0..60 {
        let st = rpc("getSignatureStatuses", json!([[sig]])).await;
        let s = &st["value"][0];
        if !s.is_null() && s["confirmationStatus"] != "processed" {
            assert!(s["err"].is_null(), "setup tx failed: {s}");
            return sig;
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    panic!("setup tx {sig} not confirmed")
}

fn base64_encode(b: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(b)
}

async fn airdrop(to: &Key, lamports: u64) {
    let sig = rpc("requestAirdrop", json!([b58(to), lamports])).await;
    for _ in 0..60 {
        let st = rpc("getSignatureStatuses", json!([[sig]])).await;
        if st["value"][0]["confirmationStatus"].as_str().is_some_and(|s| s != "processed") {
            return;
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    panic!("airdrop never confirmed");
}

async fn token_balance(account: &Key) -> u64 {
    let v = rpc("getTokenAccountBalance", json!([b58(account), {"commitment": "confirmed"}])).await;
    v["value"]["amount"].as_str().unwrap().parse().unwrap()
}

fn signer(name: &str) -> LocalSigner {
    LocalSigner::new(Curve::Ed25519, &sha256(&[name.as_bytes()])).unwrap()
}

fn pk(s: &LocalSigner) -> Key {
    s.public_key().try_into().unwrap()
}

/// Mint SPL Token / Token-2022 (82 byte, không extension), authority = `admin`.
async fn create_mint(admin: &LocalSigner, mint: &LocalSigner, tp: &Key) {
    let rent = rpc("getMinimumBalanceForRentExemption", json!([82])).await.as_u64().unwrap();
    let mut create = 0u32.to_le_bytes().to_vec();
    create.extend_from_slice(&rent.to_le_bytes());
    create.extend_from_slice(&82u64.to_le_bytes());
    create.extend_from_slice(tp);
    let mut init = vec![20u8, 6];
    init.extend_from_slice(&pk(admin));
    init.push(0);
    send(
        vec![
            Ix { program: SYSTEM, accounts: vec![meta(pk(admin), true, true), meta(pk(mint), true, true)], data: create },
            Ix { program: *tp, accounts: vec![meta(pk(mint), false, true)], data: init },
        ],
        &[admin, mint],
    )
    .await;
}

/// ATA(owner, mint) idempotent + mint_to.
async fn mint_to(admin: &LocalSigner, owner: &Key, mint: &Key, tp: &Key, amount: u64) -> Key {
    let a = ata(owner, mint, tp);
    let create = Ix {
        program: key(ATA_PROGRAM).unwrap(),
        accounts: vec![meta(pk(admin), true, true), meta(a, false, true), meta(*owner, false, false), meta(*mint, false, false),
            meta(SYSTEM, false, false), meta(*tp, false, false)],
        data: vec![1],
    };
    let mut d = vec![7u8];
    d.extend_from_slice(&amount.to_le_bytes());
    let mint_ix = Ix { program: *tp, accounts: vec![meta(*mint, false, true), meta(a, false, true), meta(pk(admin), true, false)], data: d };
    send(vec![create, mint_ix], &[admin]).await;
    a
}

// ------------------------------------------------------------------ fake Odoo (same transitions as e2e.rs)

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
    ingests: u32,
    indexed_block: u64,
    /// `blockchain.token.address` = mint thật (base58).
    tokens: Vec<String>,
    inflight: Vec<Value>,
}

async fn fake(State(s): State<Arc<Mutex<FakeOdoo>>>, Path((model, method)): Path<(String, String)>, Json(body): Json<Value>) -> Json<Value> {
    let mut o = s.lock().unwrap();
    let out = match (model.as_str(), method.as_str()) {
        ("blockchain.chain", "node_config") => json!({
            "finality_mode": "tag", "finality_depth": 0, "finality_quorum": 1, "indexed_block": o.indexed_block,
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

/// `relay_pay` của alice (ví seed R32, kind 0 = ký thẳng `T`) thành job `signed_op`.
#[allow(clippy::too_many_arguments)]
fn job(id: i64, network: &Key, alice: &LocalSigner, mint: &Key, tp: &str, to: &Key, amount: u64, ref_byte: u8, lane_byte: u8, valid_until: u64) -> (Value, [u8; 32]) {
    let program = key(PROGRAM).unwrap();
    let from = pk(alice);
    let op = MetaOp {
        network: *network,
        contract: account_of(&program, &from),
        asset: *mint,
        op: 0,
        from,
        to: *to,
        amount: amount as u128,
        pay_ref: [ref_byte; 32],
        lane: [lane_byte; 32],
        nonce: 0,
        valid_until,
        relayer: [0; 32],
        extra: [0; 32],
    };
    let digest = op.digest();
    let t = format!("scaas.metaop.v1:{}", alloy::hex::encode(digest));
    let mut blob = vec![0u8, 0];
    blob.extend_from_slice(&alice.sign(t.as_bytes()).unwrap());
    let j = json!({"id": id, "kind": "signed_op", "op": {
        "family": "solana", "contract": b58(&op.contract), "from": b58(&from), "op_kind": "pay",
        "payload": alloy::hex::encode(op.encode()), "signature": alloy::hex::encode(&blob),
        "public_key": alloy::hex::encode(from), "auth_kind": "wallet", "digest": format!("0x{}", alloy::hex::encode(digest)),
        "valid_until": valid_until, "extra": {"asset": b58(mint), "token_program": tp}}});
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

fn cfg(network: &str) -> ChainCfg {
    let mut params = toml::Table::new();
    params.insert("program_id".into(), toml::Value::String(PROGRAM.into()));
    ChainCfg {
        family: "solana".into(),
        network: Some(network.into()),
        rpc_urls: vec![RPC.into()],
        lanes: vec![0, 1],
        params,
        finality: FinalityCfg { mode: "tag".into(), depth: 0, quorum: 1 },
        poll_ms: 200,
        ..Default::default()
    }
}

#[tokio::test]
#[ignore]
async fn solana_payments_relay_finalize_and_never_lock_each_other() {
    let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();
    let program = key(PROGRAM).unwrap();
    let genesis = rpc("getGenesisHash", json!([])).await.as_str().unwrap().to_string();
    let network = key(&genesis).unwrap();

    // initialize: only the upgrade authority set at genesis (`--upgradeable-program … <authority>`).
    let authority = signer("e2e-upgrade-authority");
    assert_eq!(b58(&pk(&authority)), "73VoVWyfxmaWC6gUjsse6xzNTLLoEhazMCcKakXWbebm", "the validator's --upgradeable-program authority");
    airdrop(&pk(&authority), 100_000_000_000).await;
    let loader = key("BPFLoaderUpgradeab1e11111111111111111111111").unwrap();
    let mut data = discriminator("global", "initialize").to_vec();
    data.extend_from_slice(&network);
    data.extend_from_slice(&pk(&authority));
    let init = Ix {
        program,
        accounts: vec![meta(pk(&authority), true, true), meta(find_pda(&[b"config"], &program).0, false, true), meta(program, false, false),
            meta(find_pda(&[&program], &loader).0, false, false), meta(SYSTEM, false, false)],
        data,
    };
    send(vec![init], &[&authority]).await;

    // Mints: SPL Token (USD), Token-2022 (EUR) and an unregistered SPL mint (EVIL). Alice has no SOL at all.
    let (usd_kp, eur_kp, evil_kp) = (signer("e2e-usd"), signer("e2e-eur"), signer("e2e-evil"));
    let (tok, t22) = (key(TOKEN_PROGRAM).unwrap(), key(TOKEN_2022).unwrap());
    create_mint(&authority, &usd_kp, &tok).await;
    create_mint(&authority, &eur_kp, &t22).await;
    create_mint(&authority, &evil_kp, &tok).await;
    let (usd, eur, evil) = (pk(&usd_kp), pk(&eur_kp), pk(&evil_kp));
    let alice = signer("alice");
    let acct = account_of(&program, &pk(&alice));
    mint_to(&authority, &acct, &usd, &tok, 100_000).await;
    mint_to(&authority, &acct, &eur, &t22, 100_000).await;
    mint_to(&authority, &acct, &evil, &tok, 100_000).await;
    let shop = pk(&signer("shop"));

    // Two lanes from the 24-word mnemonic.
    let seed = Seed::from_words(MNEMONIC, None).unwrap();
    let signers: Vec<LocalSigner> = [0u32, 1]
        .iter()
        .map(|&i| {
            let (curve, secret) = lane_secret(&seed, "solana", i).unwrap();
            LocalSigner::new(curve, &secret).unwrap()
        })
        .collect();
    for s in &signers {
        airdrop(&pk(s), 10_000_000_000).await;
    }
    let adapter = scaas_node::adapters::build(&cfg(&genesis), &signers).unwrap();
    assert_eq!(adapter.chain_key(), format!("solana:{genesis}"));
    assert_eq!(adapter.lanes()[0].address, "3Cy3YNTFywCmxoxt8n7UH6hg6dLo5uACowX3CFceaSnx");
    assert!(adapter.lane_balance(0).await.unwrap().unwrap() > 0);
    // first `sequence` creates the lane's deterministic durable nonce account
    let s0 = adapter.sequence(0).await.unwrap();
    let nonce0 = nonce_account(&pk(&signers[0]));
    assert!(!rpc("getAccountInfo", json!([b58(&nonce0), {"commitment": "confirmed"}])).await["value"].is_null());
    assert_eq!(adapter.sequence(0).await.unwrap(), s0, "stable until a tx advances it");
    // M1: someone squats lane 1's public nonce address with lamports before its first use; creation still works
    let nonce1 = nonce_account(&pk(&signers[1]));
    airdrop(&nonce1, 1_000_000).await;
    adapter.sequence(1).await.unwrap();
    let n1 = rpc("getAccountInfo", json!([b58(&nonce1), {"commitment": "confirmed", "encoding": "base64"}])).await;
    assert_eq!(n1["value"]["space"].as_u64(), Some(80), "pre-funded address became the lane's nonce account");

    let state = Arc::new(Mutex::new(FakeOdoo { tokens: vec![b58(&usd), b58(&eur)], ..Default::default() }));
    let odoo = odoo_at(start_fake(state.clone()).await);
    let head0 = adapter.final_head().await.unwrap().expect("finalized head");
    state.lock().unwrap().indexed_block = head0.height;

    // ANTI-LOCK: X `signed` on lane 0 and held; Y (Token-2022, another Odoo lane) goes all the way on lane 1.
    let vu = now() + 600;
    let (x, x_digest) = job(1, &network, &alice, &usd, TOKEN_PROGRAM, &shop, 1000, 0x11, 0xa1, vu);
    let (y, y_digest) = job(2, &network, &alice, &eur, TOKEN_2022, &shop, 500, 0x22, 0xa2, vu);
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
    assert_eq!(token_balance(&ata(&shop, &usd, &tok)).await, 1000);
    assert_eq!(token_balance(&ata(&shop, &eur, &t22)).await, 500);
    // Self-computed tx id = the signature the cluster recorded; fee = lane signature + precompile signature.
    let x_id = state.lock().unwrap().reports.iter().find(|r| r["job_id"] == 1 && r["chain_state"] == "signed").unwrap()["tx_hash"]
        .as_str()
        .unwrap()
        .to_string();
    let x_sig = b58(&alloy::hex::decode(x_id.trim_start_matches("0x")).unwrap());
    let x_tx = rpc("getTransaction", json!([x_sig, {"commitment": "confirmed", "maxSupportedTransactionVersion": 1}])).await;
    assert_eq!(x_tx["transaction"]["signatures"][0], json!(x_sig));
    assert!(x_tx["meta"]["err"].is_null());
    assert_eq!(x_tx["version"], json!(1), "a v1 transaction");
    assert_eq!(x_tx["meta"]["fee"].as_u64().unwrap() % 5000, 0);
    println!("relay_pay: fee {} lamports, {} CU", x_tx["meta"]["fee"], x_tx["meta"]["computeUnitsConsumed"]);
    assert_eq!(adapter.tx_fee(&x_id).await.unwrap(), x_tx["meta"]["fee"].as_u64().map(u128::from));
    // Replay X: the lane PDA nonce is used ⇒ simulation refuses ⇒ `consumed` (R80), nothing paid.
    let mut replay = x;
    replay["id"] = json!(3);
    assert_eq!(run_job(adapter.as_ref(), &odoo, &state, 0, replay).await, ["consumed"]);

    // REJECTED: bytes signed over a nonce value that has since advanced.
    let (r6, _) = job(6, &network, &alice, &usd, TOKEN_PROGRAM, &shop, 10, 0x66, 0xa6, vu);
    let r6: Job = serde_json::from_value(r6).unwrap();
    let stale = adapter.sign(adapter.build(&r6, 0).await.unwrap(), 0, adapter.sequence(0).await.unwrap()).await.unwrap();
    let (adv, _) = job(61, &network, &alice, &usd, TOKEN_PROGRAM, &shop, 10, 0x61, 0xb6, vu);
    assert_eq!(run_job(adapter.as_ref(), &odoo, &state, 0, adv).await, ["signed", "broadcast", "mined"]);
    let err = adapter.submit(&stale).await.unwrap_err();
    assert!(err.downcast_ref::<Rejected>().is_some(), "{err:#}");
    assert_eq!(adapter.tx_status(&stale.tx_id).await.unwrap(), TxStatus::Unknown);

    // RESTART. A: broadcast before the crash ⇒ the new process's recover_lane settles it mined.
    let (a7, _) = job(7, &network, &alice, &usd, TOKEN_PROGRAM, &shop, 70, 0x77, 0xa7, vu);
    let a7: Job = serde_json::from_value(a7).unwrap();
    let s7 = adapter.sign(adapter.build(&a7, 0).await.unwrap(), 0, adapter.sequence(0).await.unwrap()).await.unwrap();
    adapter.submit(&s7).await.unwrap();
    // B: signed (journaled) but never sent, payload still valid for minutes.
    let (b8, _) = job(8, &network, &alice, &usd, TOKEN_PROGRAM, &shop, 80, 0x88, 0xa8, vu);
    let b8: Job = serde_json::from_value(b8).unwrap();
    let s8 = adapter.sign(adapter.build(&b8, 1).await.unwrap(), 1, adapter.sequence(1).await.unwrap()).await.unwrap();
    drop(adapter);
    let adapter = scaas_node::adapters::build(&cfg(&genesis), &signers).unwrap(); // new process
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
        "payload": {"id": 8, "kind": "signed_op", "op": {"valid_until": vu}}})];
    let t = std::time::Instant::now();
    tokio::time::timeout(Duration::from_secs(60), recover_lane(adapter.as_ref(), &odoo, 1, "e2e")).await.expect("recovery B").unwrap();
    assert_eq!(states_of(&state, 8), ["queued"], "requeued at once, not held until the payload expires");
    assert!(t.elapsed() < Duration::from_secs(30));
    assert!(adapter.submit(&s8).await.unwrap_err().downcast_ref::<Rejected>().is_some(), "old bytes can never land");

    // L2: a payment in an unregistered mint lands but is never reported.
    let (e10, _) = job(10, &network, &alice, &evil, TOKEN_PROGRAM, &shop, 33, 0xaa, 0xaa, vu);
    assert_eq!(run_job(adapter.as_ref(), &odoo, &state, 1, e10).await, ["signed", "broadcast", "mined"]);

    // I1: the same relay_pay wrapped in ANOTHER program's CPI (test-only forwarder) is still reported.
    let (w12, w_digest) = job(12, &network, &alice, &usd, TOKEN_PROGRAM, &shop, 12, 0xcc, 0xcc, vu);
    let w_op = MetaOp::decode(&alloy::hex::decode(w12["op"]["payload"].as_str().unwrap()).unwrap()).unwrap();
    let w_auth = parse_auth(w12["op"]["signature"].as_str().unwrap(), w12["op"]["public_key"].as_str().unwrap()).unwrap();
    let pay = Pay { program, lane: pk(&signers[0]), op: &w_op, auth: &w_auth, token_program: key(TOKEN_PROGRAM).unwrap(), subject_exists: true };
    let mut inner = relay_pay_ix(&pay);
    assert_eq!(inner.data[226], 1, "Auth.precompile_ix");
    inner.data[226] = 0; // no AdvanceNonce here: the precompile is instruction 0
    let mut accounts = vec![meta(program, false, false)];
    accounts.extend(inner.accounts);
    let wrapped = Ix { program: key(WRAPPER).unwrap(), accounts, data: inner.data };
    let w_sig = send(vec![auth_ix(&w_auth, &w_op.digest()), wrapped], &[&signers[0]]).await;
    let w_tx = rpc("getTransaction", json!([w_sig, {"commitment": "confirmed", "maxSupportedTransactionVersion": 1}])).await;
    assert!(w_tx["meta"]["logMessages"].as_array().unwrap().iter().any(|l| l.as_str() == Some(&format!("Program {PROGRAM} invoke [2]"))), "relay_pay ran as a CPI");

    // Finality: index until X, Y, R6-advance, A and the wrapped pay are reported (finalized lags ~32 slots).
    for _ in 0..240 {
        while index_step(adapter.as_ref(), &odoo).await.unwrap() {}
        if state.lock().unwrap().ingested.iter().filter(|e| e["event"] == "PaymentSettled").count() >= 5 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let ing = state.lock().unwrap().ingested.clone();
    let settled: Vec<&Value> = ing.iter().filter(|e| e["event"] == "PaymentSettled").collect();
    assert_eq!(settled.len(), 5, "X, Y, 61, A, wrapped — not EVIL: {ing:#?}");
    let pay_w = settled.iter().find(|e| e["entry_ref"] == json!(format!("0x{}", "cc".repeat(32)))).expect("wrapped pay settled");
    assert_eq!(pay_w["amount"].as_str(), Some("12"));
    let pay_x = settled.iter().find(|e| e["entry_ref"] == json!(format!("0x{}", "11".repeat(32)))).expect("X settled");
    assert_eq!((pay_x["contract"].as_str(), pay_x["to"].as_str(), pay_x["amount"].as_str()), (Some(b58(&usd).as_str()), Some(b58(&shop).as_str()), Some("1000")));
    assert_eq!(pay_x["from"], json!(b58(&pk(&alice))));
    assert_eq!(pay_x["tx_hash"], json!(x_id));
    let pay_y = settled.iter().find(|e| e["entry_ref"] == json!(format!("0x{}", "22".repeat(32)))).expect("Y settled");
    assert_eq!(pay_y["contract"], json!(b58(&eur)), "Token-2022 mint");
    for d in [x_digest, y_digest, w_digest] {
        assert!(ing.iter().any(|e| e["event"] == "MetaTransactionExecuted" && e["digest"] == json!(format!("0x{}", alloy::hex::encode(d)))));
    }
    assert!(ing.iter().all(|e| e["block_hash"].as_str().unwrap().len() == 66 && e["tx_hash"].as_str().unwrap().len() == 130));
    assert!(state.lock().unwrap().refused.is_empty(), "{:#?}", state.lock().unwrap().refused);

    // Empty token list ⇒ no ingest, the cursor holds (L1).
    let (cursor, ingests) = {
        let mut o = state.lock().unwrap();
        o.tokens.clear();
        o.indexed_block = o.indexed_block.saturating_sub(5);
        (o.indexed_block, o.ingests)
    };
    assert!(!index_step(adapter.as_ref(), &odoo).await.unwrap());
    let o = state.lock().unwrap();
    assert_eq!((o.indexed_block, o.ingests), (cursor, ingests));
}
