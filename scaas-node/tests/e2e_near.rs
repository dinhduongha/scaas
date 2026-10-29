//! cd scaas-node && ../scripts/capped cargo test -j2 --test e2e_near -- --ignored --nocapture
//!
//! near-algorand Task 19 (spec §3.7, §3.9, §5, §7; R10, R11). Needs `smartcontracts/scripts/build.sh near` (the wasm and
//! the near-sandbox binary near-workspaces downloads for `test.sh near`). The first test starts near-sandbox itself
//! (`smartcontracts/scripts/devnet.sh near up`, inside this capped run; it stops when this process exits) and deploys
//! with `smartcontracts/scripts/deploy.sh near` — keyless: tokens TKA and TKB, the DEX, the relay-fee router and its
//! executor, every lane registered on both tokens, every access key deleted — then the tests share that chain, each on
//! its own lane pair with its own fake Odoo (as e2e_aptos.rs). Proves:
//! (T19 fix 1: every relayer is an implicit account, as the node's lanes are; the action fees are the RPC's.)
//! 1. the deploy gate fails on an account with a key left, and the node halts on one (`start_check`);
//! 2. a plain pay is relayed to `mined`, its hash = the RPC's, a replay is `consumed`, a stale nonce `Rejected`, and the
//!    indexer reports `PaymentSettled` + `MetaTransactionExecuted`;
//! 3. pay-meta (`PaymentMeta`), a relay-fee wrapper (ed25519, and the largest shape: a 12-passkey msig
//!    `relay_fee_mandate_open` + a passkey payment), the escrow router to a real DEX settle (released), to a failing
//!    target (refunded) and to a target still in flight past its deadline (the node's `relay_timeout`, refund wins);
//! 4. native NEP-141 `ft_transfer` / `transfer_to_ua` moves are indexed, an unregistered token's are not;
//! 5. two lanes do not block each other (a held signed transaction on one, the other runs to `mined`).
//!
//! Gas, the action-fee constants and `max_gas_burnt_view` are printed (`GAS` / `FEES` lines) for the run log.
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::extract::{Path, State};
use axum::routing::post;
use axum::{Json, Router};
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use scaas_node::adapter::{index_step, lane_step, Built, ChainAdapter, Family, Head, Lane, Rejected, Signed, TxStatus};
use scaas_node::adapters::near::{self as nr, meta_pay_id, pay_lane, relay_ref, router_call, Holder, MetaOp, TGAS};
use scaas_node::chain::SimError;
use scaas_node::config::{ChainCfg, FinalityCfg, OdooCfg, TokenCfg};
use scaas_node::keys::{lane_secret, Seed};
use scaas_node::odoo::{Job, Odoo};
use scaas_node::signer::{LocalSigner, Signer};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
/// Lanes 2k, 2k + 1 belong to test k.
const LANES: u32 = 18;
const NEAR: u128 = 1_000_000_000_000_000_000_000_000;
/// yoctoNEAR per base unit of TKA / TKB: a fee of `FEE` = 1 NEAR covers any job here.
const PRICE: &str = "1000000000000000000000";
const FEE: u128 = 1000;
const FIXTURE: &str = "fixture.test.near";
const RP: &str = "pay.scaas.test";
const ORIGIN: &str = "https://pay.scaas.test";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

fn vu() -> u64 {
    now() + 3_600
}

fn sha(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

fn keccak(b: &[u8]) -> [u8; 32] {
    alloy::primitives::keccak256(b).0
}

fn hex(b: &[u8]) -> String {
    alloy::hex::encode(b)
}

fn x(b: &[u8]) -> String {
    format!("0x{}", hex(b))
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn b64d(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}

fn b58(b: &[u8]) -> String {
    bs58::encode(b).into_string()
}

// ------------------------------------------------------------------ Borsh

fn bvec(b: &[u8]) -> Vec<u8> {
    [&(b.len() as u32).to_le_bytes()[..], b].concat()
}

fn bstr(s: &str) -> Vec<u8> {
    bvec(s.as_bytes())
}

fn len8(s: &str) -> Vec<u8> {
    [&[s.len() as u8][..], s.as_bytes()].concat()
}

fn holder(h: &Holder) -> Vec<u8> {
    match h {
        Holder::Near(a) => [&[0u8][..], &bstr(a)].concat(),
        Holder::Ua(id) => [&[1u8][..], id].concat(),
    }
}

// ------------------------------------------------------------------ SCaaS signers (common/src/{auth,hash,ua}.rs)

fn ua(tag: &str, key_data: &[u8]) -> [u8; 32] {
    keccak(&[&keccak(tag.as_bytes())[..], key_data].concat())
}

/// `sha256(u32 LE 2^31+413 ‖ Borsh { "scaas.metaop.v1:" ‖ hex(digest), nonce = digest, recipient, None })`.
fn nep413(digest: &[u8; 32], recipient: &str) -> [u8; 32] {
    let text = format!("scaas.metaop.v1:{}", hex(digest));
    sha(&[&((1u32 << 31) + 413).to_le_bytes()[..], &bstr(&text), digest, &bstr(recipient), &[0]].concat())
}

/// An ed25519 SCaaS key (UA kind 0x0102).
struct Ed(SigningKey);

impl Ed {
    fn new(tag: &str) -> Self {
        Ed(SigningKey::from_bytes(&sha(tag.as_bytes())))
    }
    fn pk(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
    fn h(&self) -> Holder {
        Holder::Ua(ua("scaas.ua.ed25519.v1", &self.pk()))
    }
    fn auth(&self, op: &MetaOp) -> Vec<u8> {
        let sig = self.0.sign(&nep413(&op.digest(), &op.contract)).to_bytes();
        [&[0u8][..], &self.pk(), &sig].concat()
    }
}

/// A P-256 passkey of `RP` (UA kind 0x0100), asserting from `ORIGIN` (Chrome's clientDataJSON).
struct Pk(p256::ecdsa::SigningKey);

impl Pk {
    fn new(seed: u8) -> Self {
        Pk(p256::ecdsa::SigningKey::from_bytes(&[seed; 32].into()).unwrap())
    }
    fn raw(&self) -> Vec<u8> {
        self.0.verifying_key().to_encoded_point(false).as_bytes()[1..].to_vec()
    }
    fn id(&self) -> [u8; 32] {
        ua("scaas.ua.webauthn-p256.v1", &[self.raw(), sha(RP.as_bytes()).to_vec()].concat())
    }
    fn h(&self) -> Holder {
        Holder::Ua(self.id())
    }
    fn auth(&self, op: &MetaOp) -> Vec<u8> {
        let d = op.digest();
        let ad = [&sha(RP.as_bytes())[..], &[0x05, 0, 0, 0, 0]].concat();
        let c = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(d);
        let cd = format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"{ORIGIN}","crossOrigin":false}}"#);
        let sig: p256::ecdsa::Signature = self.0.sign_prehash(&sha(&[&ad[..], &sha(cd.as_bytes())].concat())).unwrap();
        let sig = sig.normalize_s().unwrap_or(sig).to_bytes();
        [&[2u8][..], &self.raw(), &bvec(&ad), &bvec(cd.as_bytes()), &sig[..]].concat()
    }
}

// ------------------------------------------------------------------ the shared chain

struct World {
    rpc: String,
    home: PathBuf,
    net: [u8; 32],
    net_b58: String,
    funder: SigningKey,
    tka: String,
    tkb: String,
    dex: String,
    router: String,
    exec: String,
    /// A second router whose executor is the target fixture (its `exec` waits until `resume`: a call stays in flight,
    /// which the real executor never lets happen), both keyless: the node's timeout path.
    slow_router: String,
    slow_exec: String,
}

static WORLD: tokio::sync::OnceCell<World> = tokio::sync::OnceCell::const_new();
/// The funding account's next nonce (tests run in parallel and share it).
static FUNDER_NONCE: tokio::sync::Mutex<u64> = tokio::sync::Mutex::const_new(0);

async fn world() -> &'static World {
    WORLD.get_or_init(start).await
}

fn lane_signer(i: u32) -> LocalSigner {
    let seed = Seed::from_words(MNEMONIC, None).unwrap();
    let (curve, secret) = lane_secret(&seed, "near", i).unwrap();
    LocalSigner::new(curve, &secret).unwrap()
}

fn lane_id(i: u32) -> String {
    hex(&lane_signer(i).public_key())
}

fn script(rel: &str, args: &[&str], env: &[(&str, String)]) -> Output {
    let mut c = Command::new(root().join(rel));
    c.args(args);
    for (k, v) in env {
        c.env(k, v);
    }
    c.output().unwrap_or_else(|e| panic!("{rel}: {e}"))
}

fn ok_out(what: &str, o: &Output) -> String {
    let (so, se) = (String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    assert!(o.status.success(), "{what} failed: {so}{se}");
    so.into_owned()
}

/// near-sandbox up (stopped with this process), keyless deploy, lanes funded, the test-only target fixture deployed
/// (with a key: it is not a SCaaS account), TKA / TKB minted to the funding account (the tokens' admin).
async fn start() -> World {
    let home = std::env::temp_dir().join("scaas-near-e2e");
    let _ = std::fs::remove_dir_all(&home);
    let h = home.to_str().unwrap().to_string();
    let pid = std::process::id().to_string();
    let up = script("smartcontracts/scripts/devnet.sh", &["near", "up", &h], &[("NEAR_SANDBOX_WATCH_PID", pid)]);
    let rpc = ok_out("devnet.sh near up", &up).trim().to_string();
    let cfg: Value = serde_json::from_str(&std::fs::read_to_string(home.join("config.json")).unwrap()).unwrap();
    println!("FEES max_gas_burnt_view = {} Tgas (sandbox config.json)", cfg["max_gas_burnt_view"].as_u64().unwrap() / TGAS);
    assert!(cfg["max_gas_burnt_view"].as_u64().unwrap() >= 300 * TGAS, "the relayer's RPC needs max_gas_burnt_view >= 300 Tgas");
    let lanes: Vec<String> = (0..LANES).map(lane_id).collect();
    let env = [
        ("NEAR_KEY_FILE", format!("{h}/validator_key.json")),
        ("NEAR_TOKENS", "TKA:Token A:6,TKB:Token B:6".to_string()),
        ("NEAR_LANES", lanes.join(",")),
        ("NEAR_DEPLOYMENTS_DIR", format!("{h}/deployments")),
    ];
    let out = script("smartcontracts/scripts/deploy.sh", &["near", &rpc], &env);
    println!("{}", ok_out("deploy.sh near", &out));
    let key: Value = serde_json::from_str(&std::fs::read_to_string(home.join("validator_key.json")).unwrap()).unwrap();
    let sk = bs58::decode(key["secret_key"].as_str().unwrap().strip_prefix("ed25519:").unwrap()).into_vec().unwrap();
    let funder = SigningKey::from_bytes(&sk[..32].try_into().unwrap());
    let st = rpc_at(&rpc, "status", json!([])).await;
    let net_b58 = st["genesis_hash"].as_str().unwrap().to_string();
    let dep: Value = serde_json::from_str(&std::fs::read_to_string(home.join(format!("deployments/{net_b58}.json"))).unwrap()).unwrap();
    let s = |k: &str| dep[k].as_str().unwrap().to_string();
    let w = World {
        rpc,
        home,
        net: bs58::decode(&net_b58).into_vec().unwrap().try_into().unwrap(),
        net_b58,
        funder,
        tka: dep["tokens"][0]["account"].as_str().unwrap().into(),
        tkb: dep["tokens"][1]["account"].as_str().unwrap().into(),
        dex: s("dex"),
        router: s("relayfee"),
        exec: s("relayexec"),
        slow_router: "relayslow.test.near".into(),
        slow_exec: "fxexec.test.near".into(),
    };
    for l in &lanes {
        w.funder_tx(l, vec![Act::Transfer(50 * NEAR)]).await;
    }
    let fx = std::fs::read(root().join("smartcontracts/near/target/near/scaas_near_target_fixture/scaas_near_target_fixture.wasm")).unwrap();
    let pk = w.funder.verifying_key().to_bytes();
    w.funder_tx(FIXTURE, vec![Act::Create, Act::Transfer(5 * NEAR), Act::FullKey(pk), Act::Deploy(fx)]).await;
    w.keyless(&w.slow_exec, "scaas_near_target_fixture", None).await;
    w.keyless(&w.slow_router, "scaas_near_relayfee", Some(("new", bstr(&w.slow_exec)))).await;
    for t in [&w.tka, &w.tkb] {
        w.call(t, "mint", json!({"to": "test.near", "amount": "1000000000000"}), NEAR / 10).await;
    }
    w
}

/// One action of a funder transaction (nearcore `Action` Borsh).
enum Act {
    Create,
    Deploy(Vec<u8>),
    Call(String, Vec<u8>, u64, u128),
    Transfer(u128),
    FullKey([u8; 32]),
    DeleteKey([u8; 32]),
}

impl Act {
    fn borsh(&self) -> Vec<u8> {
        match self {
            Act::Create => vec![0],
            Act::Deploy(c) => [&[1u8][..], &bvec(c)].concat(),
            Act::Call(m, a, g, d) => [&[2u8][..], &bstr(m), &bvec(a), &g.to_le_bytes(), &d.to_le_bytes()].concat(),
            Act::Transfer(d) => [&[3u8][..], &d.to_le_bytes()].concat(),
            Act::FullKey(pk) => [&[5u8, 0][..], pk, &0u64.to_le_bytes(), &[1]].concat(),
            Act::DeleteKey(pk) => [&[6u8, 0][..], pk].concat(),
        }
    }
}

async fn rpc_at(url: &str, method: &str, params: Value) -> Value {
    let body = json!({"jsonrpc": "2.0", "id": "e2e", "method": method, "params": params});
    let v: Value = reqwest::Client::new().post(url).json(&body).send().await.unwrap().json().await.unwrap();
    assert!(v["error"].is_null(), "{method}: {v}");
    v["result"].clone()
}

impl World {
    async fn rpc(&self, method: &str, params: Value) -> Value {
        rpc_at(&self.rpc, method, params).await
    }

    async fn view(&self, account: &str, method: &str, args: &[u8]) -> Vec<u8> {
        let v = self.rpc("query", json!({"request_type": "call_function", "finality": "final", "account_id": account,
            "method_name": method, "args_base64": b64(args)})).await;
        v["result"].as_array().unwrap_or_else(|| panic!("{method}: {v}")).iter().map(|b| b.as_u64().unwrap() as u8).collect()
    }

    async fn balance(&self, token: &str, h: &Holder) -> u128 {
        let (m, a) = match h {
            Holder::Near(a) => ("ft_balance_of", json!({"account_id": a})),
            Holder::Ua(id) => ("ua_balance_of", json!({"id": id.to_vec()})),
        };
        let v: String = serde_json::from_slice(&self.view(token, m, &serde_json::to_vec(&a).unwrap()).await).unwrap();
        v.parse().unwrap()
    }

    /// A transaction of the funding account `test.near`, to `FINAL`; every receipt must succeed.
    async fn funder_tx(&self, receiver: &str, acts: Vec<Act>) -> Value {
        let mut n = FUNDER_NONCE.lock().await;
        if *n == 0 {
            *n = self.key_nonce("test.near").await;
        }
        *n += 1;
        self.tx_as("test.near", *n, receiver, acts).await
    }

    /// The access-key nonce of the funding key on `account`.
    async fn key_nonce(&self, account: &str) -> u64 {
        let pk = self.funder.verifying_key().to_bytes();
        let k = self.rpc("query", json!({"request_type": "view_access_key", "finality": "optimistic", "account_id": account,
            "public_key": format!("ed25519:{}", b58(&pk))})).await;
        k["nonce"].as_u64().unwrap()
    }

    /// A transaction of `signer` with the funding key (test.near, or an account the e2e created with that key), to
    /// `FINAL`; every receipt must succeed.
    async fn tx_as(&self, signer: &str, nonce: u64, receiver: &str, acts: Vec<Act>) -> Value {
        let pk = self.funder.verifying_key().to_bytes();
        let block = bs58::decode(self.rpc("block", json!({"finality": "final"})).await["header"]["hash"].as_str().unwrap()).into_vec().unwrap();
        let mut tx = [bstr(signer), vec![0], pk.to_vec(), nonce.to_le_bytes().to_vec(), bstr(receiver), block].concat();
        tx.extend_from_slice(&(acts.len() as u32).to_le_bytes());
        for a in &acts {
            tx.extend(a.borsh());
        }
        let sig = self.funder.sign(&sha(&tx)).to_bytes();
        let signed = [tx, vec![0], sig.to_vec()].concat();
        let r = self.rpc("send_tx", json!({"signed_tx_base64": b64(&signed), "wait_until": "FINAL"})).await;
        let failed: Vec<&Value> = r["receipts_outcome"].as_array().unwrap().iter().filter(|o| o["outcome"]["status"].get("Failure").is_some()).collect();
        assert!(r["status"].get("Failure").is_none() && failed.is_empty(), "{signer} tx to {receiver}: {} {failed:?}", r["status"]);
        r
    }

    /// A keyless contract account `id` (as deploy.sh makes them): created with the funding key and `wasm`, initialised
    /// by itself (`init`: method, Borsh args), then its only key deleted.
    async fn keyless(&self, id: &str, wasm: &str, init: Option<(&str, Vec<u8>)>) {
        let code = std::fs::read(root().join("smartcontracts/near/target/near").join(wasm).join(format!("{wasm}.wasm"))).unwrap();
        let pk = self.funder.verifying_key().to_bytes();
        self.funder_tx(id, vec![Act::Create, Act::Transfer(10 * NEAR), Act::FullKey(pk), Act::Deploy(code)]).await;
        let mut acts: Vec<Act> = init.map(|(m, a)| Act::Call(m.into(), a, 100 * TGAS, 0)).into_iter().collect();
        acts.push(Act::DeleteKey(pk));
        self.tx_as(id, self.key_nonce(id).await + 1, id, acts).await;
    }

    async fn call(&self, receiver: &str, method: &str, args: Value, deposit: u128) -> Value {
        self.funder_tx(receiver, vec![Act::Call(method.into(), serde_json::to_vec(&args).unwrap(), 100 * TGAS, deposit)]).await
    }

    /// `transfer_to_ua` from the funding account (a new UA record: its storage attached, the excess refunded).
    async fn fund(&self, token: &str, h: &Holder, amount: u128) {
        let Holder::Ua(id) = h else { panic!("UA only") };
        self.call(token, "transfer_to_ua", json!({"id": id.to_vec(), "amount": amount.to_string()}), NEAR / 10).await;
    }

    /// A NEAR account's balance (yoctoNEAR, final).
    async fn near(&self, a: &str) -> u128 {
        let v = self.rpc("query", json!({"request_type": "view_account", "finality": "final", "account_id": a})).await;
        v["amount"].as_str().unwrap().parse().unwrap()
    }

    async fn head(&self) -> u64 {
        self.rpc("block", json!({"finality": "final"})).await["header"]["height"].as_u64().unwrap()
    }

    async fn tx(&self, tx_hash: &str, sender: &str) -> Value {
        let h = b58(&alloy::hex::decode(tx_hash.trim_start_matches("0x")).unwrap());
        self.rpc("EXPERIMENTAL_tx_status", json!({"tx_hash": h, "sender_account_id": sender, "wait_until": "NONE"})).await
    }

    fn op(&self, token: &str, code: u8, from: &Holder, to: &Holder) -> MetaOp {
        MetaOp {
            network: self.net,
            contract: token.into(),
            op: code,
            from: from.clone(),
            to: to.clone(),
            relayer: None,
            amount: 0,
            pay_ref: [0; 32],
            lane: [0; 32],
            nonce: 0,
            valid_until: vu(),
            extra: [0; 32],
        }
    }

    /// A routed payment (spec §3.8): op 0, `pay_ref = r`, `lane = payLane(r)`, nonce 0, `relayer = marker`, `extra = salt`.
    fn fee_op(&self, token: &str, from: &Holder, to: &Holder, marker: &str, r: [u8; 32], salt: [u8; 32]) -> MetaOp {
        MetaOp { amount: FEE, pay_ref: r, lane: pay_lane(&r), relayer: Some(marker.into()), extra: salt, ..self.op(token, 0, from, to) }
    }

    fn params(&self, dex: &str, targets: bool) -> toml::Table {
        let mut t = format!(
            r#"dex = "{dex}"
[relay_fee]
router = "{}"
executor = "{}"
min_amount = 1
min_yocto_value = {{ "{}" = "{PRICE}", "{}" = "{PRICE}" }}
"#,
            self.router, self.exec, self.tka, self.tkb
        );
        if targets {
            t.push_str(&format!("targets = {{ \"{FIXTURE}\" = [\"ok\", \"fail\", \"wait\"] }}\n"));
        }
        toml::from_str(&t).unwrap()
    }

    fn cfg(&self, k: u32) -> ChainCfg {
        ChainCfg {
            family: "near".into(),
            network: Some(self.net_b58.clone()),
            rpc_urls: vec![self.rpc.clone()],
            lanes: vec![2 * k, 2 * k + 1],
            tokens: [&self.tka, &self.tkb].map(|t| TokenCfg { address: t.clone(), decimals: 6 }).to_vec(),
            params: self.params(&self.dex, true),
            finality: FinalityCfg { mode: "instant".into(), depth: 0, quorum: 1 },
            poll_ms: 200,
            ..Default::default()
        }
    }

    /// Test `k`'s adapter on lanes 2k, 2k + 1 (start-checked).
    async fn adapter(&self, k: u32) -> Arc<dyn ChainAdapter> {
        let a = scaas_node::adapters::build(&self.cfg(k), &[lane_signer(2 * k), lane_signer(2 * k + 1)]).unwrap();
        a.start_check().await.unwrap();
        a
    }
}

// ------------------------------------------------------------------ fake Odoo (as e2e_aptos.rs)

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
}

async fn fake(State(s): State<Arc<Mutex<FakeOdoo>>>, Path((model, method)): Path<(String, String)>, Json(body): Json<Value>) -> Json<Value> {
    let mut o = s.lock().unwrap();
    let out = match (model.as_str(), method.as_str()) {
        ("blockchain.chain", "node_config") => json!({
            "finality_mode": "instant", "finality_depth": 0, "finality_quorum": 1, "indexed_block": o.indexed_block,
            "tokens": o.tokens.iter().map(|a| json!({"address": a, "decimals": 6})).collect::<Vec<_>>(),
            "journal_max_nonce": null, "inflight": []}),
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
            // as the real Odoo: an event of a token it has not registered is refused (L2)
            for e in body["events"].as_array().unwrap() {
                if !o.tokens.iter().any(|t| Some(t.as_str()) == e["contract"].as_str()) {
                    o.refused.push(e.clone());
                }
            }
            o.indexed_block = body["to_block"].as_u64().unwrap();
            o.ingested.extend(body["events"].as_array().unwrap().iter().cloned());
            json!({"indexed_block": o.indexed_block, "created": 0})
        }
        _ => json!({"error": "unexpected"}),
    };
    Json(out)
}

/// A fake Odoo registering `tokens`, its cursor at the current final head.
async fn odoo(w: &World, tokens: &[&String]) -> (Odoo, Arc<Mutex<FakeOdoo>>) {
    let state = Arc::new(Mutex::new(FakeOdoo {
        tokens: tokens.iter().map(|t| t.to_string()).collect(),
        indexed_block: w.head().await,
        ..Default::default()
    }));
    let app = Router::new().route("/json/2/{model}/{method}", post(fake)).with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let cfg = OdooCfg { url: format!("http://{addr}"), database: "t".into(), relay_api_key_env: String::new(), indexer_api_key_env: String::new() };
    (Odoo::with_key(&cfg, "k".into()).unwrap(), state)
}

fn states_of(state: &Arc<Mutex<FakeOdoo>>, id: i64) -> Vec<String> {
    state.lock().unwrap().reports.iter().filter(|r| r["job_id"] == id).map(|r| r["chain_state"].as_str().unwrap().to_string()).collect()
}

fn report(state: &Arc<Mutex<FakeOdoo>>, id: i64, chain_state: &str) -> Value {
    state.lock().unwrap().reports.iter().find(|r| r["job_id"] == id && r["chain_state"] == chain_state).cloned()
        .unwrap_or_else(|| panic!("job {id}: no {chain_state} report"))
}

async fn run_job(a: &dyn ChainAdapter, odoo: &Odoo, state: &Arc<Mutex<FakeOdoo>>, lane: usize, j: Value) -> Vec<String> {
    let id = j["id"].as_i64().unwrap();
    state.lock().unwrap().jobs.push(j);
    let ran = tokio::time::timeout(Duration::from_secs(180), lane_step(a, odoo, lane, "e2e")).await.expect("lane_step stuck");
    assert!(ran.unwrap());
    let st = states_of(state, id);
    if st.last().map(String::as_str) != Some("mined") {
        dump(state, id).await;
    }
    st
}

/// A job that did not end `mined`: its reports and, when sent, every receipt (executor, gas, status, logs).
async fn dump(state: &Arc<Mutex<FakeOdoo>>, id: i64) {
    let reps: Vec<Value> = state.lock().unwrap().reports.iter().filter(|r| r["job_id"] == id).cloned().collect();
    println!("job {id}: {reps:#?}");
    let Some(s) = reps.iter().find(|r| r["chain_state"] == "signed") else { return };
    let w = world().await;
    let t = w.tx(s["tx_hash"].as_str().unwrap(), s["signer_address"].as_str().unwrap()).await;
    for o in t["receipts_outcome"].as_array().into_iter().flatten() {
        let o = &o["outcome"];
        println!("  receipt {} {:.3} Tgas {} {:?}", o["executor_id"], o["gas_burnt"].as_u64().unwrap_or(0) as f64 / 1e12, o["status"], o["logs"]);
    }
}

/// A `signed_op` job of `op` + `auth`; `extra` = the job kind's fields of `op`.
fn job(id: i64, op: &MetaOp, auth: &[u8], extra: Value) -> Value {
    let mut o = json!({"family": "near", "contract": op.contract, "payload": hex(&op.encode()), "signature": hex(auth),
                       "valid_until": op.valid_until});
    for (k, v) in extra.as_object().unwrap() {
        o[k] = v.clone();
    }
    json!({"id": id, "kind": "signed_op", "op": o})
}

/// Indexes until `done(rows)` (≤ 120 s); a range with a transaction not final yet is retried.
async fn index_until(a: &dyn ChainAdapter, odoo: &Odoo, state: &Arc<Mutex<FakeOdoo>>, done: impl Fn(&[Value]) -> bool) -> Vec<Value> {
    for _ in 0..240 {
        while let Ok(true) = index_step(a, odoo).await {}
        let rows = state.lock().unwrap().ingested.clone();
        if done(&rows) {
            return rows;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("indexer never reported the rows: {:#?}", state.lock().unwrap().ingested);
}

fn rows_of<'a>(rows: &'a [Value], event: &str, r: &[u8; 32]) -> Vec<&'a Value> {
    rows.iter().filter(|e| e["event"] == event && e["entry_ref"] == x(r)).collect()
}

/// `(total gas burnt by the transaction, the first receipt's burnt gas, prepaid gas)` in Tgas.
async fn gas_of(w: &World, tx_hash: &str, lane: &str) -> (f64, f64, f64) {
    let t = w.tx(tx_hash, lane).await;
    let burnt: u64 = std::iter::once(&t["transaction_outcome"]).chain(t["receipts_outcome"].as_array().unwrap())
        .map(|o| o["outcome"]["gas_burnt"].as_u64().unwrap()).sum();
    let first = t["receipts_outcome"][0]["outcome"]["gas_burnt"].as_u64().unwrap();
    let prepaid = t["transaction"]["actions"][0]["FunctionCall"]["gas"].as_u64().unwrap();
    let tg = |g: u64| g as f64 / TGAS as f64;
    (tg(burnt), tg(first), tg(prepaid))
}

/// T19 review I1: the node's quote for job `j` (its call as the lane sent it, its kind from the job; prepaid gas + action
/// fees (+ a `relay_timeout` for a router job) at the chain's gas price, plus the attached deposit) covers what the job
/// actually cost the lane: its NEAR balance decrease from `before` until the job's transaction and `more` (e.g. the node's
/// `relay_timeout`) are final. The fee the lane receives is token units (NEP-141), not NEAR, so the decrease is net of
/// nothing. Prints a QUOTE line.
#[allow(clippy::too_many_arguments)]
async fn quote_covers(w: &World, cfg: &ChainCfg, j: &Value, tx_hash: &str, lane: &str, more: &[String], before: u128, what: &str) {
    let fees = nr::ActionFees::from_protocol_config(&w.rpc("EXPERIMENTAL_protocol_config", json!({"finality": "final"})).await).unwrap();
    let policy = nr::RelayFeePolicy::from_cfg(cfg).unwrap();
    let op = MetaOp::decode(&alloy::hex::decode(j["op"]["payload"].as_str().unwrap()).unwrap()).unwrap();
    let entry = nr::entry(&policy, &op, &j["op"]).unwrap();
    let h = b58(&alloy::hex::decode(tx_hash.trim_start_matches("0x")).unwrap());
    let t = w.rpc("EXPERIMENTAL_tx_status", json!({"tx_hash": h, "sender_account_id": lane, "wait_until": "FINAL"})).await;
    for m in more {
        w.rpc("EXPERIMENTAL_tx_status", json!({"tx_hash": m, "sender_account_id": lane, "wait_until": "FINAL"})).await;
    }
    let fc = &t["transaction"]["actions"][0]["FunctionCall"];
    let call = nr::Call {
        receiver: t["transaction"]["receiver_id"].as_str().unwrap().into(),
        method: fc["method_name"].as_str().unwrap().into(),
        args: b64d(fc["args"].as_str().unwrap()),
        gas: fc["gas"].as_u64().unwrap(),
        deposit: fc["deposit"].as_str().unwrap().parse().unwrap(),
    };
    let price: u128 = w.rpc("gas_price", json!([null])).await["gas_price"].as_str().unwrap().parse().unwrap();
    let quote = u128::from(nr::quote_gas(&fees, &entry, &call)) * price + call.deposit;
    let spent = before.saturating_sub(w.near(lane).await);
    let n = |y: u128| y as f64 / NEAR as f64;
    println!("QUOTE {what}: quote {:.6} NEAR >= the lane's NEAR decrease {:.6} (deposit {:.6}, gas price {price})", n(quote), n(spent), n(call.deposit));
    assert!(quote >= spent, "{what}: the quote {quote} yocto under-prices the lane's {spent} yocto decrease");
}

/// The lane's transactions to `receiver` calling `method` in blocks `from..=head` (base58 hashes).
async fn lane_txs(w: &World, lane: &str, receiver: &str, method: &str, from: u64) -> Vec<String> {
    let mut out = vec![];
    for h in from..=w.head().await {
        let Ok(b) = rpc_try(&w.rpc, "block", json!({"block_id": h})).await else { continue };
        for c in b["chunks"].as_array().unwrap() {
            let ch = w.rpc("chunk", json!({"chunk_id": c["chunk_hash"]})).await;
            for t in ch["transactions"].as_array().unwrap() {
                if t["signer_id"] == lane && t["receiver_id"] == receiver && t["actions"][0]["FunctionCall"]["method_name"] == method {
                    out.push(t["hash"].as_str().unwrap().to_string());
                }
            }
        }
    }
    out
}

async fn rpc_try(url: &str, method: &str, params: Value) -> Result<Value, Value> {
    let body = json!({"jsonrpc": "2.0", "id": "e2e", "method": method, "params": params});
    let v: Value = reqwest::Client::new().post(url).json(&body).send().await.unwrap().json().await.unwrap();
    if v["error"].is_null() { Ok(v["result"].clone()) } else { Err(v["error"].clone()) }
}

// ------------------------------------------------------------------ tests

/// R10 / spec §3.9: the deployment passes its own gate (deploy.sh ran it before writing the file); an account with a key
/// left fails it, and the node halts on such an account (`start_check`).
#[tokio::test]
#[ignore]
async fn deploy_gate_fails_with_a_key_left() {
    let w = world().await;
    let ids = [&w.tka, &w.tkb, &w.dex, &w.router, &w.exec].map(|s| s.as_str());
    let pass = script("smartcontracts/scripts/deploy.sh", &[&["near", &w.rpc, "gate"][..], &ids].concat(), &[]);
    assert!(ok_out("gate", &pass).contains("5 accounts keyless"));
    let dep: Value = serde_json::from_str(&std::fs::read_to_string(w.home.join(format!("deployments/{}.json", w.net_b58))).unwrap()).unwrap();
    assert_eq!(dep["network"], w.net_b58);
    assert_eq!(dep["lanes"].as_array().unwrap().len(), LANES as usize);
    // a key left: the fixture holds code and a full-access key
    let fail = script("smartcontracts/scripts/deploy.sh", &["near", &w.rpc, "gate", &w.tka, FIXTURE], &[]);
    let err = String::from_utf8_lossy(&fail.stderr);
    assert!(!fail.status.success(), "the gate passed an account with a key");
    assert!(err.contains("deploy gate FAILED") && err.contains(&format!("{FIXTURE} has 1 access key(s)")) && !err.contains(&w.tka), "{err}");
    // the node: a configured contract with a key halts the chain
    let mut c = w.cfg(0);
    c.params = w.params(FIXTURE, false);
    let a = scaas_node::adapters::build(&c, &[lane_signer(0), lane_signer(1)]).unwrap();
    let e = format!("{:#}", a.start_check().await.unwrap_err());
    assert!(e.contains(&format!("dex {FIXTURE} has an access key: the chain is halted")), "{e}");
    // the deployed set starts
    let a = w.adapter(0).await;
    assert_eq!(a.chain_key(), format!("near:{}", w.net_b58));
    assert_eq!(a.lanes()[0].address, lane_id(0));
}

/// Review I3: `deploy.sh near` checks NEAR_LANES before any chain step; a deploy killed once its first account exists
/// leaves its temporary key in the 0600 resume file (that account fails the gate); a rerun resumes and ends keyless, the
/// gate passing, the deployment written and the resume file gone; a third run does nothing new and passes again.
#[tokio::test]
#[ignore]
async fn deploy_resumes_after_an_interruption() {
    use std::os::unix::fs::PermissionsExt;
    let w = world().await;
    let f = "dep2.test.near";
    let pk = w.funder.verifying_key().to_bytes();
    w.funder_tx(f, vec![Act::Create, Act::Transfer(60 * NEAR), Act::FullKey(pk)]).await;
    let dir = w.home.join("deploy2");
    std::fs::create_dir_all(&dir).unwrap();
    let key = dir.join("key.json");
    let secret = format!("ed25519:{}", b58(&[w.funder.to_bytes(), pk].concat()));
    std::fs::write(&key, json!({"account_id": f, "secret_key": secret}).to_string()).unwrap();
    let env = |lanes: String| vec![
        ("NEAR_KEY_FILE", key.to_str().unwrap().to_string()),
        ("NEAR_TOKENS", "TKA:Token A:6".to_string()),
        ("NEAR_LANES", lanes),
        ("NEAR_DEPLOYMENTS_DIR", dir.to_str().unwrap().to_string()),
    ];
    let lanes = format!("{},{}", lane_id(0), lane_id(1));
    let token = format!("tka.{f}");
    let exists = |a: String| async move { rpc_try(&w.rpc, "query", json!({"request_type": "view_account", "finality": "final", "account_id": a})).await.is_ok() };
    // a malformed lane id: refused before any transaction
    let bad = script("smartcontracts/scripts/deploy.sh", &["near", &w.rpc], &env(format!("{},XYZ", lane_id(0))));
    assert!(!bad.status.success() && String::from_utf8_lossy(&bad.stderr).contains("NEAR_LANES"), "{bad:?}");
    assert!(!exists(token.clone()).await, "nothing deployed");
    // interrupted: killed once the first account exists
    let mut c = Command::new(root().join("smartcontracts/scripts/deploy.sh"));
    c.args(["near", &w.rpc]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
    for (k, v) in env(lanes.clone()) {
        c.env(k, v);
    }
    let mut child = c.spawn().unwrap();
    let mut created = false;
    for _ in 0..600 {
        if exists(token.clone()).await {
            created = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(created, "the first account never appeared");
    let resume = dir.join(format!("{}.{f}.resume.json", w.net_b58));
    assert_eq!(std::fs::metadata(&resume).expect("resume file kept").permissions().mode() & 0o777, 0o600);
    let half = script("smartcontracts/scripts/deploy.sh", &["near", &w.rpc, "gate", &token], &[]);
    assert!(!half.status.success(), "the interrupted account still holds its temporary key");
    // the rerun resumes and finishes
    let out = script("smartcontracts/scripts/deploy.sh", &["near", &w.rpc], &env(lanes.clone()));
    let log = ok_out("deploy.sh near (resumed)", &out);
    println!("{log}");
    assert!(log.contains("resuming") && log.contains("deploy gate: 4 accounts keyless"), "{log}");
    assert!(!resume.exists(), "the resume file is removed after the gate");
    let dep: Value = serde_json::from_str(&std::fs::read_to_string(dir.join(format!("{}.json", w.net_b58))).unwrap()).unwrap();
    assert_eq!(dep["tokens"][0]["account"], token.as_str());
    for l in [lane_id(0), lane_id(1)] {
        let v: Value = serde_json::from_slice(&w.view(&token, "storage_balance_of", &serde_json::to_vec(&json!({"account_id": l})).unwrap()).await).unwrap();
        assert!(!v.is_null(), "lane {l} registered");
    }
    // a third run: every step already done
    let again = ok_out("deploy.sh near (again)", &script("smartcontracts/scripts/deploy.sh", &["near", &w.rpc], &env(lanes)));
    assert!(again.contains("deployed and initialised") && !again.contains("create ") && again.contains("4 accounts keyless"), "{again}");
}

/// A plain `mtx_pay` relayed to `mined`; its hash = the RPC's; a replay is `consumed`; a stale nonce is `Rejected` before
/// the pool; `PaymentSettled` + `MetaTransactionExecuted` indexed.
#[tokio::test]
#[ignore]
async fn near_pay_relay_finalize() {
    let w = world().await;
    let a = w.adapter(1).await;
    assert!(a.lane_balance(0).await.unwrap().unwrap() > 0);
    let (odoo, state) = odoo(w, &[&w.tka]).await;
    let (alice, shop) = (Ed::new("pay-alice"), Ed::new("pay-shop").h());
    w.fund(&w.tka, &alice.h(), 100_000).await;
    let op = MetaOp { amount: 1000, pay_ref: [0x11; 32], lane: [0xa1; 32], ..w.op(&w.tka, 0, &alice.h(), &shop) };
    let j = job(1, &op, &alice.auth(&op), json!({}));
    let b0 = w.near(&lane_id(2)).await;
    assert_eq!(run_job(a.as_ref(), &odoo, &state, 0, j.clone()).await, ["signed", "broadcast", "mined"]);
    quote_covers(w, &w.cfg(1), &j, report(&state, 1, "signed")["tx_hash"].as_str().unwrap(), &lane_id(2), &[], b0, "mtx_pay").await;
    assert_eq!((w.balance(&w.tka, &alice.h()).await, w.balance(&w.tka, &shop).await), (99_000, 1000));
    let hash = report(&state, 1, "signed")["tx_hash"].as_str().unwrap().to_string();
    let t = w.tx(&hash, &lane_id(2)).await;
    assert_eq!(t["transaction"]["hash"].as_str().unwrap(), b58(&alloy::hex::decode(&hash[2..]).unwrap()), "own hash = the RPC's");
    let (burnt, first, prepaid) = gas_of(w, &hash, &lane_id(2)).await;
    println!("GAS mtx_pay (ed25519): {burnt:.3} Tgas burnt in all, {first:.3} in its receipt, {prepaid:.0} prepaid (pin 21 + 1: GAS_JOB_BASE = 10 + IMPLICIT_TRANSFER_GAS 11)");
    // replay: the lane nonce is spent ⇒ consumed (no gas)
    let mut replay = j;
    replay["id"] = json!(2);
    assert_eq!(run_job(a.as_ref(), &odoo, &state, 0, replay).await, ["consumed"]);
    // a stale access-key nonce: refused before the pool
    let op3 = MetaOp { amount: 10, pay_ref: [0x13; 32], lane: [0xa3; 32], ..w.op(&w.tka, 0, &alice.h(), &shop) };
    let j3: Job = serde_json::from_value(job(3, &op3, &alice.auth(&op3), json!({}))).unwrap();
    let seq = a.sequence(0).await.unwrap();
    let stale = a.sign(a.build(&j3, 0).await.unwrap(), 0, seq - 1).await.unwrap();
    let err = a.submit(&stale).await.unwrap_err();
    assert!(err.downcast_ref::<Rejected>().is_some() && format!("{err}").contains("InvalidNonce"), "{err:#}");
    let rows = index_until(a.as_ref(), &odoo, &state, |r| !rows_of(r, "PaymentSettled", &[0x11; 32]).is_empty()
        && r.iter().any(|e| e["event"] == "MetaTransactionExecuted" && e["digest"] == x(&op.digest()))).await;
    let p = rows_of(&rows, "PaymentSettled", &[0x11; 32])[0];
    assert_eq!((p["contract"].as_str(), p["from"].as_str(), p["to"].as_str(), p["amount"].as_str()),
        (Some(w.tka.as_str()), Some(alice.h().display().as_str()), Some(shop.display().as_str()), Some("1000")));
    assert_eq!(p["tx_hash"], hash);
    assert!(rows.iter().all(|e| e["block_hash"].as_str().unwrap().len() == 66));
    assert!(state.lock().unwrap().refused.is_empty(), "{:#?}", state.lock().unwrap().refused);
}

/// CTR-MTX-26 pay-meta: `pay_ref = metaPayId(salt, meta)`, `lane = payLane`, nonce 0 ⇒ `mtx_pay_meta`, `PaymentMeta`
/// indexed with the meta bytes; a pay-meta whose `pay_ref` does not commit to them dies before simulation.
#[tokio::test]
#[ignore]
async fn near_pay_meta_job() {
    let w = world().await;
    let a = w.adapter(2).await;
    let (odoo, state) = odoo(w, &[&w.tka]).await;
    let (alice, shop) = (Ed::new("meta-alice"), Ed::new("meta-shop").h());
    w.fund(&w.tka, &alice.h(), 10_000).await;
    let (salt, meta) = ([0x5a; 32], b"invoice 42 / near e2e".to_vec());
    let id = meta_pay_id(&salt, &meta);
    let op = MetaOp { amount: 700, pay_ref: id, lane: pay_lane(&id), ..w.op(&w.tka, 0, &alice.h(), &shop) };
    let kind = json!({"kind": "pay_meta", "salt": hex(&salt), "meta": hex(&meta)});
    let j = job(1, &op, &alice.auth(&op), kind.clone());
    let b0 = w.near(&lane_id(4)).await;
    assert_eq!(run_job(a.as_ref(), &odoo, &state, 0, j.clone()).await, ["signed", "broadcast", "mined"]);
    quote_covers(w, &w.cfg(2), &j, report(&state, 1, "signed")["tx_hash"].as_str().unwrap(), &lane_id(4), &[], b0, "mtx_pay_meta").await;
    assert_eq!(w.balance(&w.tka, &shop).await, 700);
    let bad = MetaOp { amount: 1, pay_ref: [0x77; 32], lane: pay_lane(&[0x77; 32]), ..w.op(&w.tka, 0, &alice.h(), &shop) };
    assert_eq!(run_job(a.as_ref(), &odoo, &state, 1, job(2, &bad, &alice.auth(&bad), kind)).await, ["dead"]);
    // `payment_meta` joins its `payment_settled` (indexer::join_pay_events): the row carries `meta`
    let rows = index_until(a.as_ref(), &odoo, &state, |r| !rows_of(r, "PaymentSettled", &id).is_empty()).await;
    let p = rows_of(&rows, "PaymentSettled", &id)[0];
    assert_eq!((p["meta"].as_str(), p["amount"].as_str()), (Some(x(&meta).as_str()), Some("700")));
    assert!(rows.iter().all(|e| e["event"] != "PaymentMeta"), "never a row of its own");
}

/// Spec §3.8 wrappers: an ed25519 `relay_fee_add_origin` (entry subject opened lazily) paid in open mode to the lane, and
/// the largest wrapper (a 12-passkey msig `relay_fee_mandate_open` + a passkey payment, 13 passkeys: prepaid 10 + 13 × 21
/// Tgas); burnt gas against the pins, the action-fee constants against the RPC's protocol config.
#[tokio::test]
#[ignore]
async fn near_relay_fee_wrapper_job() {
    let w = world().await;
    let a = w.adapter(3).await;
    let lane = lane_id(6);
    let (odoo, state) = odoo(w, &[&w.tka]).await;
    // FEES: the node's pinned nearcore RuntimeFeesConfig against the sandbox's (a lane transaction is never sir)
    let pc = w.rpc("EXPERIMENTAL_protocol_config", json!({"finality": "final"})).await;
    let tc = &pc["runtime_config"]["transaction_costs"];
    let fee = |v: &Value| (v["send_not_sir"].as_u64().unwrap(), v["execution"].as_u64().unwrap());
    let (rc, fc, fb) = (fee(&tc["action_receipt_creation_config"]), fee(&tc["action_creation_config"]["function_call_cost"]),
        fee(&tc["action_creation_config"]["function_call_cost_per_byte"]));
    println!("FEES sandbox protocol {}: receipt {rc:?}, function call {fc:?}, per byte {fb:?} (send_not_sir, execution); node pins 108059500000, 2319861500000, 2235934 each",
        pc["protocol_version"]);
    // ruling B: the node reads these at start (max(send, exec) per item, charged twice): never below the real fees
    let fees = nr::ActionFees::from_protocol_config(&pc).unwrap();
    let node = nr::NearAdapter::new(&w.cfg(3), &[lane_signer(6), lane_signer(7)]).unwrap();
    assert_eq!(node.fees().await.unwrap(), fees, "the node prices the chain's own action fees");
    println!("FEES the node's (read from the RPC): {fees:?}");
    for n in [321usize, 16_384, 65_536] {
        let call = nr::Call { receiver: w.tka.clone(), method: "relay_fee_mandate_open".into(), args: vec![0; n], gas: 0, deposit: 0 };
        let real = rc.0 + rc.1 + fc.0 + fc.1 + (fb.0 + fb.1) * (call.method.len() + n) as u64;
        let priced = nr::action_fees(&fees, &call);
        println!("FEES a lane call with {n} B of args: node prices {:.3} Tgas of action fees, the sandbox charges {:.3}", priced as f64 / 1e12, real as f64 / 1e12);
        assert!(priced >= real, "the node's action fees under-price a {n} B call");
    }
    println!("FEES timeout resend priced at {:.3} Tgas", nr::timeout_gas(&fees) as f64 / TGAS as f64);

    // ed25519: entry mtx_add_origin by an unopened subject, the payment by another payer, open mode (to = the token)
    let (subject, payer) = (Ed::new("wrap-subject"), Ed::new("wrap-payer"));
    w.fund(&w.tka, &payer.h(), 10_000).await;
    let origin = bstr("https://app.scaas.test");
    let eop = MetaOp { extra: sha(&origin), ..w.op(&w.tka, 8, &subject.h(), &subject.h()) };
    let call = [len8("mtx_add_origin"), eop.borsh(), subject.auth(&eop), origin].concat();
    let salt = [0x5b; 32];
    let r = relay_ref(&w.net, &len8(&w.tka), &call, &salt);
    let pay = w.fee_op(&w.tka, &payer.h(), &Holder::Near(w.tka.clone()), &w.tka, r, salt);
    let kind = json!({"kind": "relay_fee", "extra": {"route": "wrapper", "call": hex(&call)}});
    let lane_h = Holder::Near(lane.clone());
    let l0 = w.balance(&w.tka, &lane_h).await;
    let j = job(1, &pay, &payer.auth(&pay), kind);
    let b0 = w.near(&lane).await;
    assert_eq!(run_job(a.as_ref(), &odoo, &state, 0, j.clone()).await, ["signed", "broadcast", "mined"]);
    quote_covers(w, &w.cfg(3), &j, report(&state, 1, "signed")["tx_hash"].as_str().unwrap(), &lane, &[], b0, "relay_fee_add_origin (ed25519)").await;
    assert_eq!(w.balance(&w.tka, &lane_h).await - l0, FEE, "open mode: the fee reaches the submitting lane");
    assert_eq!(w.balance(&w.tka, &payer.h()).await, 10_000 - FEE);
    let hash = report(&state, 1, "signed")["tx_hash"].as_str().unwrap().to_string();
    let (burnt, first, prepaid) = gas_of(w, &hash, &lane).await;
    println!("GAS relay_fee_add_origin (ed25519 entry + ed25519 payment): {burnt:.3} Tgas burnt in all, {first:.3} in its receipt, {prepaid:.0} prepaid (pin 21 + 1 + 1)");
    assert!(first <= prepaid);

    // the largest shape: 12-passkey msig mandate_open (threshold 12) + a passkey payment
    let py = Pk::new(2);
    w.fund(&w.tka, &py.h(), 10_000).await;
    let mut ms: Vec<Pk> = (20..32).map(Pk::new).collect();
    ms.sort_by_key(Pk::id);
    let body: Vec<u8> = ms.iter().flat_map(|s| [&0x0100u16.to_be_bytes()[..], &s.id(), &[0, 1]].concat()).collect();
    let kd = [&[0u8, 12, 0, 12][..], &body].concat();
    let m = Holder::Ua(ua("scaas.ua.msig.v1", &kd));
    w.fund(&w.tka, &m, 1_000).await;
    // MandateTerms { delegate, payee, per_payment, per_period, period_s, expiry, funding }
    let terms = [holder(&Ed::new("wrap-delegate").h()), holder(&Ed::new("wrap-payee").h()), 100u128.to_le_bytes().to_vec(),
        250u128.to_le_bytes().to_vec(), 3_600u64.to_le_bytes().to_vec(), vu().to_le_bytes().to_vec(), 1_000u128.to_le_bytes().to_vec()].concat();
    let mlane = [0xb0; 32];
    let id = sha(&[holder(&m), terms.clone(), mlane.to_vec(), 0u64.to_le_bytes().to_vec()].concat());
    let eop = MetaOp { amount: 1_000, lane: mlane, extra: sha(&[&id[..], &terms].concat()), ..w.op(&w.tka, 13, &m, &Holder::Ua(id)) };
    let mut auth = [vec![3u8], bvec(&kd), 12u32.to_le_bytes().to_vec()].concat();
    for (i, s) in ms.iter().enumerate() {
        auth.push(i as u8);
        auth.extend(s.auth(&eop));
    }
    let call = [len8("mtx_mandate_open"), eop.borsh(), auth, terms].concat();
    let salt = [0x5c; 32];
    let r = relay_ref(&w.net, &len8(&w.tka), &call, &salt);
    let pay = w.fee_op(&w.tka, &py.h(), &Holder::Near(w.tka.clone()), &w.tka, r, salt);
    let kind = json!({"kind": "relay_fee", "extra": {"route": "wrapper", "call": hex(&call)}});
    let j = job(2, &pay, &py.auth(&pay), kind);
    let b0 = w.near(&lane_id(7)).await;
    assert_eq!(run_job(a.as_ref(), &odoo, &state, 1, j.clone()).await, ["signed", "broadcast", "mined"]);
    quote_covers(w, &w.cfg(3), &j, report(&state, 2, "signed")["tx_hash"].as_str().unwrap(), &lane_id(7), &[], b0, "relay_fee_mandate_open (13 passkeys)").await;
    assert_eq!(w.balance(&w.tka, &Holder::Ua(id)).await, 1_000, "the mandate funded");
    let hash2 = report(&state, 2, "signed")["tx_hash"].as_str().unwrap().to_string();
    let (burnt, first, prepaid) = gas_of(w, &hash2, &lane_id(7)).await;
    println!("GAS relay_fee_mandate_open (12-passkey msig entry + passkey payment, 13 passkeys): {burnt:.3} Tgas burnt in all, {first:.3} in its receipt, {prepaid:.0} prepaid (pin 21 + 13 x 21 = 294), headroom {:.3} Tgas",
        prepaid - first);
    assert!(prepaid == 294.0 && first <= prepaid);

    // `relay_fee_paid` joins its `payment_settled` (relay_target = the token, relay_payee = the lane)
    let rows = index_until(a.as_ref(), &odoo, &state, |rows| rows_of(rows, "PaymentSettled", &r).iter().any(|p| p["relay_payee"].is_string())).await;
    let p = rows_of(&rows, "PaymentSettled", &r)[0];
    assert_eq!((p["relay_target"].as_str(), p["relay_payee"].as_str(), p["to"].as_str(), p["amount"].as_str()),
        (Some(w.tka.as_str()), Some(lane_id(7).as_str()), Some(lane_id(7).as_str()), Some("1000")));
    assert!(rows.iter().filter(|e| e["relay_target"].is_string()).count() >= 2 && rows.iter().all(|e| e["event"] != "RelayFeePaid"));
    assert!(state.lock().unwrap().refused.is_empty(), "{:#?}", state.lock().unwrap().refused);
}

/// Two crossing orders (one bound to the executor, one open), each leg's extra = sha256(order); `settle` relayed through
/// the router: released (`on_settle` true), the fee to the lane, both legs paid out, the trade rows carry `leg_digest`
/// and `settle_id`, `RelayFeePaid` from the router.
#[tokio::test]
#[ignore]
async fn near_router_release() {
    let w = world().await;
    let a = w.adapter(4).await;
    let lane = lane_id(8);
    let (odoo, state) = odoo(w, &[&w.tka, &w.tkb]).await;
    let (s1, s2, payer) = (Ed::new("dex-s1"), Ed::new("dex-s2"), Ed::new("dex-payer"));
    w.fund(&w.tka, &s1.h(), 500).await;
    w.fund(&w.tkb, &s2.h(), 300).await;
    w.fund(&w.tka, &payer.h(), 10_000).await;
    let order = |sell: &str, buy: &str, n: u128, min: u128, relayer: Option<&str>| {
        let r = match relayer {
            None => vec![0u8],
            Some(a) => [vec![1u8], bstr(a)].concat(),
        };
        [bstr(sell), bstr(buy), n.to_le_bytes().to_vec(), min.to_le_bytes().to_vec(), r, vu().to_le_bytes().to_vec()].concat()
    };
    let leg = |s: &Ed, token: &str, n: u128, o: &[u8], lane: u8| {
        let op = MetaOp { amount: n, lane: [lane; 32], relayer: Some(w.dex.clone()), extra: sha(o),
            ..w.op(token, 1, &s.h(), &Holder::Near(w.dex.clone())) };
        [o.to_vec(), op.borsh(), s.auth(&op)].concat()
    };
    let (oa, ob) = (order(&w.tka, &w.tkb, 500, 300, Some(&w.exec)), order(&w.tkb, &w.tka, 300, 500, None));
    let args = [leg(&s1, &w.tka, 500, &oa, 0xc1), leg(&s2, &w.tkb, 300, &ob, 0xc2)].concat();
    let call = router_call(&w.dex, "settle", &args);
    let salt = [0x6a; 32];
    let r = relay_ref(&w.net, &len8(&w.dex), &call, &salt);
    let pay = w.fee_op(&w.tka, &payer.h(), &Holder::Near(w.router.clone()), &w.router, r, salt);
    let kind = json!({"kind": "relay_fee", "extra": {"route": "router", "call": hex(&call), "target_gas": "0", "target_deposit": "0"}});
    let lane_h = Holder::Near(lane.clone());
    let l0 = w.balance(&w.tka, &lane_h).await;
    let j = job(1, &pay, &payer.auth(&pay), kind);
    let b0 = w.near(&lane).await;
    assert_eq!(run_job(a.as_ref(), &odoo, &state, 0, j.clone()).await, ["signed", "broadcast", "mined"]);
    quote_covers(w, &w.cfg(4), &j, report(&state, 1, "signed")["tx_hash"].as_str().unwrap(), &lane, &[], b0, "router -> dex.settle (released)").await;
    assert_eq!((w.balance(&w.tkb, &s1.h()).await, w.balance(&w.tka, &s2.h()).await), (300, 500), "both legs paid out");
    assert_eq!((w.balance(&w.tka, &s1.h()).await, w.balance(&w.tkb, &s2.h()).await), (0, 0));
    assert_eq!(w.balance(&w.tka, &lane_h).await - l0, FEE, "open mode: the router pays the relaying lane");
    assert_eq!(w.view(&w.router, "pending", &r).await, vec![0], "the escrow holds nothing");
    let hash = report(&state, 1, "signed")["tx_hash"].as_str().unwrap().to_string();
    let (burnt, first, prepaid) = gas_of(w, &hash, &lane).await;
    println!("GAS router relay -> dex.settle (ed25519 payment, two ed25519 legs): {burnt:.3} Tgas burnt in all, {first:.3} in relay, {prepaid:.0} prepaid (102 + 1 + settle 27 + 2 x 18)");
    // the router's `relay_fee_paid` joins the token's `payment_settled` (relay_target = the DEX, relay_payee = the lane)
    let rows = index_until(a.as_ref(), &odoo, &state, |rows| rows_of(rows, "PaymentSettled", &r).iter().any(|p| p["relay_payee"].is_string())
        && rows.iter().filter(|e| e["event"] == "Transfer" && e["settle_id"].is_string()).count() >= 2).await;
    let p = rows_of(&rows, "PaymentSettled", &r)[0];
    assert_eq!((p["contract"].as_str(), p["relay_target"].as_str(), p["relay_payee"].as_str(), p["to"].as_str()),
        (Some(w.tka.as_str()), Some(w.dex.as_str()), Some(lane.as_str()), Some(lane.as_str())));
    let trades: Vec<&Value> = rows.iter().filter(|e| e["event"] == "Transfer" && e["settle_id"].is_string()).collect();
    assert!(trades.iter().any(|t| t["contract"] == w.tka.as_str()) && trades.iter().any(|t| t["contract"] == w.tkb.as_str()), "{trades:#?}");
    assert!(state.lock().unwrap().refused.is_empty(), "{:#?}", state.lock().unwrap().refused);
}

/// The router to a listed target whose call fails (fixture `fail`): refunded, the job reverted, the payer not charged,
/// no payment indexed under its ref.
#[tokio::test]
#[ignore]
async fn near_router_refund() {
    let w = world().await;
    let a = w.adapter(5).await;
    let (odoo, state) = odoo(w, &[&w.tka]).await;
    let payer = Ed::new("refund-payer");
    w.fund(&w.tka, &payer.h(), 10_000).await;
    let call = router_call(FIXTURE, "fail", &[]);
    let salt = [0x6b; 32];
    let r = relay_ref(&w.net, &len8(FIXTURE), &call, &salt);
    let pay = w.fee_op(&w.tka, &payer.h(), &Holder::Near(w.router.clone()), &w.router, r, salt);
    let kind = json!({"kind": "relay_fee", "extra": {"route": "router", "call": hex(&call), "target_gas": "5000000000000", "target_deposit": "0"}});
    let j = job(1, &pay, &payer.auth(&pay), kind);
    let b0 = w.near(&lane_id(10)).await;
    assert_eq!(run_job(a.as_ref(), &odoo, &state, 0, j.clone()).await, ["signed", "broadcast", "reverted"]);
    quote_covers(w, &w.cfg(5), &j, report(&state, 1, "signed")["tx_hash"].as_str().unwrap(), &lane_id(10), &[], b0, "router -> listed target fail (refunded)").await;
    let rep = report(&state, 1, "reverted");
    assert!(rep["error"].as_str().unwrap().contains("refunded"), "{rep}");
    // the refund branch proper: the hold succeeded, the target ran and failed (not a refused hold)
    let t = w.tx(report(&state, 1, "signed")["tx_hash"].as_str().unwrap(), &lane_id(10)).await;
    let ran = |who: &str, ok: bool| t["receipts_outcome"].as_array().unwrap().iter()
        .any(|o| o["outcome"]["executor_id"] == who && o["outcome"]["status"].get("Failure").is_none() == ok);
    assert!(ran(&w.tka, true) && ran(FIXTURE, false), "hold ok, target failed: {:#?}", t["receipts_outcome"]);
    assert_eq!(w.balance(&w.tka, &payer.h()).await, 10_000, "refunded: the payer is not charged");
    assert_eq!(w.view(&w.router, "pending", &r).await, vec![0]);
    let h = w.head().await;
    let rows = index_until(a.as_ref(), &odoo, &state, |_| state.lock().unwrap().indexed_block >= h).await;
    assert!(rows.iter().all(|e| e["entry_ref"] != x(&r)), "nothing settled under the ref: {rows:#?}");
}

/// A call still in flight past its deadline (patched): the node sends `relay_timeout(ref)` itself and the entry is
/// refunded; the call's late success then pays nothing (refund wins); the job ends reverted, the payer not charged, the
/// lane not paid. The real executor never leaves a call in flight (it returns the target's own receipt, T10 ruling e,
/// so a yielding target already counts as done), so this job goes through the keyless second router whose executor is
/// the fixture (`exec` waits, NEP-519, until `resume`), as the contract tests' slow router.
#[tokio::test]
#[ignore]
async fn near_router_timeout() {
    let w = world().await;
    let mut c = w.cfg(6);
    let rf = c.params.get_mut("relay_fee").and_then(|v| v.as_table_mut()).unwrap();
    rf.insert("router".into(), toml::Value::String(w.slow_router.clone()));
    rf.insert("executor".into(), toml::Value::String(w.slow_exec.clone()));
    let a = scaas_node::adapters::build(&c, &[lane_signer(12), lane_signer(13)]).unwrap();
    a.start_check().await.unwrap();
    let lane = lane_id(12);
    let (odoo, state) = odoo(w, &[&w.tka]).await;
    let payer = Ed::new("timeout-payer");
    w.fund(&w.tka, &payer.h(), 10_000).await;
    let call = router_call(FIXTURE, "ok", &[]);
    let salt = [0x6c; 32];
    let r = relay_ref(&w.net, &len8(FIXTURE), &call, &salt);
    let pay = w.fee_op(&w.tka, &payer.h(), &Holder::Near(w.slow_router.clone()), &w.slow_router, r, salt);
    let kind = json!({"kind": "relay_fee", "extra": {"route": "router", "call": hex(&call), "target_gas": "30000000000000", "target_deposit": "0"}});
    let lane_h = Holder::Near(lane.clone());
    let l0 = w.balance(&w.tka, &lane_h).await;
    let j = job(1, &pay, &payer.auth(&pay), kind);
    let b0 = w.near(&lane).await;
    state.lock().unwrap().jobs.push(j.clone());
    let h0 = w.head().await;
    let run = {
        let (a, odoo) = (a.clone(), odoo.clone());
        tokio::spawn(async move { lane_step(a.as_ref(), &odoo, 0, "e2e").await.unwrap() })
    };
    // the call in flight (stage 1 = Call): its deadline moved into the past (sandbox state patch)
    let key = [&b"p"[..], &r].concat();
    let mut patched = false;
    for _ in 0..100 {
        let v = w.rpc("query", json!({"request_type": "view_state", "finality": "final", "account_id": w.slow_router, "prefix_base64": b64(&key)})).await;
        if let Some(e) = v["values"].as_array().and_then(|a| a.first()) {
            let mut p = b64d(e["value"].as_str().unwrap());
            let n = p.len();
            if p[n - 2] == 1 {
                p[n - 10..n - 2].copy_from_slice(&(now() - 1).to_le_bytes());
                w.rpc("sandbox_patch_state", json!({"records": [{"Data": {"account_id": w.slow_router, "data_key": b64(&key), "value": b64(&p)}}]})).await;
                patched = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(patched, "the call never got in flight");
    // the node's relay_timeout refunds the entry while the call still waits
    let mut gone = false;
    for _ in 0..150 {
        if w.view(&w.slow_router, "pending", &r).await == [0] {
            gone = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(gone, "the node never timed the entry out: {:#?}", state.lock().unwrap().reports);
    assert_eq!(w.balance(&w.tka, &payer.h()).await, 10_000, "refunded");
    // the call then succeeds late: nothing is paid
    w.funder_tx(&w.slow_exec, vec![Act::Call("resume".into(), serde_json::to_vec(&json!({"ok": true})).unwrap(), 30 * TGAS, 0)]).await;
    tokio::time::timeout(Duration::from_secs(180), run).await.expect("lane stuck").unwrap();
    assert_eq!(states_of(&state, 1), ["signed", "broadcast", "reverted"]);
    let rep = report(&state, 1, "reverted");
    assert!(rep["error"].as_str().unwrap().contains("refunded"), "{rep}");
    assert_eq!((w.balance(&w.tka, &payer.h()).await, w.balance(&w.tka, &lane_h).await - l0), (10_000, 0), "refund wins");
    let timeouts = lane_txs(w, &lane, &w.slow_router, "relay_timeout", h0).await;
    assert!(!timeouts.is_empty(), "the node's relay_timeout transaction");
    quote_covers(w, &c, &j, report(&state, 1, "signed")["tx_hash"].as_str().unwrap(), &lane, &timeouts, b0, "router in flight, timed out (refunded) + relay_timeout").await;
    let seq = a.sequence(0).await.unwrap();
    let relay_nonce = report(&state, 1, "signed")["outer_nonce"].as_u64().unwrap();
    assert!(seq > relay_nonce + 1, "the lane sent relay_timeout after its relay (next nonce {seq}, relay {relay_nonce})");
}

/// NEP-141 moves outside the relayer: a native `ft_transfer` and a `transfer_to_ua` of the funding account are indexed
/// as `Transfer` rows; the same on a token Odoo has not registered (TKB) is not.
#[tokio::test]
#[ignore]
async fn near_events_include_native_ft_transfer() {
    let w = world().await;
    let a = w.adapter(7).await;
    let (odoo, state) = odoo(w, &[&w.tka]).await;
    let to = lane_id(14);
    w.call(&w.tka, "ft_transfer", json!({"receiver_id": to, "amount": "77"}), 1).await;
    w.call(&w.tkb, "ft_transfer", json!({"receiver_id": to, "amount": "88"}), 1).await;
    let u = Ed::new("native-ua").h();
    w.fund(&w.tka, &u, 99).await;
    let rows = index_until(a.as_ref(), &odoo, &state, |rows| {
        rows.iter().any(|e| e["event"] == "Transfer" && e["to"] == to.as_str() && e["amount"] == "77")
            && rows.iter().any(|e| e["event"] == "Transfer" && e["to"] == u.display().as_str())
    }).await;
    let t = rows.iter().find(|e| e["event"] == "Transfer" && e["to"] == to.as_str() && e["amount"] == "77").unwrap();
    assert_eq!((t["from"].as_str(), t["contract"].as_str()), (Some("test.near"), Some(w.tka.as_str())));
    let ua_row = rows.iter().find(|e| e["event"] == "Transfer" && e["to"] == u.display().as_str()).unwrap();
    assert_eq!((ua_row["from"].as_str(), ua_row["amount"].as_str()), (Some("test.near"), Some("99")));
    assert!(rows.iter().all(|e| e["contract"] != w.tkb.as_str() && e["amount"] != "88"), "an unregistered token is not indexed");
    assert!(state.lock().unwrap().refused.is_empty(), "{:#?}", state.lock().unwrap().refused);
}

/// The real adapter, but `submit` of job `hold` waits until the test opens `gate` (signed + journaled `signed`).
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

/// Spec §3.7 / NET-ALL-03: X signed on lane 0 and held unsent; Y on lane 1 runs to `mined` meanwhile; then X passes.
#[tokio::test]
#[ignore]
async fn near_lanes_do_not_block_each_other() {
    let w = world().await;
    let a = w.adapter(8).await;
    let (odoo, state) = odoo(w, &[&w.tka]).await;
    let (alice, shop) = (Ed::new("lanes-alice"), Ed::new("lanes-shop").h());
    w.fund(&w.tka, &alice.h(), 10_000).await;
    let op = |n: u128, b: u8| MetaOp { amount: n, pay_ref: [b; 32], lane: [b; 32], ..w.op(&w.tka, 0, &alice.h(), &shop) };
    // X's check counts alice's account and shop's record, Y creates them first: X's deposit is then excess, refunded to
    // the implicit lane within GAS_JOB_BASE (concern C, closed by T19 fix 1)
    let (ox, oy) = (op(1000, 0x21), op(500, 0x22));
    let held = Held { inner: a.clone(), hold: 1, gate: tokio::sync::Semaphore::new(0) };
    state.lock().unwrap().jobs.push(job(1, &ox, &alice.auth(&ox), json!({})));
    let x_run = lane_step(&held, &odoo, 0, "e2e");
    let y_run = async {
        while states_of(&state, 1).last().map(String::as_str) != Some("signed") {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        state.lock().unwrap().jobs.push(job(2, &oy, &alice.auth(&oy), json!({})));
        assert!(lane_step(&held, &odoo, 1, "e2e").await.unwrap());
        assert_eq!(states_of(&state, 2), ["signed", "broadcast", "mined"], "Y while X is in flight");
        assert_eq!(states_of(&state, 1), ["signed"], "X still held, unsent");
        held.gate.add_permits(1);
    };
    let joined = tokio::time::timeout(Duration::from_secs(120), async { tokio::join!(x_run, y_run) }).await;
    let Ok((x_done, ())) = joined else { panic!("lanes stuck: {:#?}", state.lock().unwrap().reports) };
    assert!(x_done.unwrap());
    if states_of(&state, 1).last().map(String::as_str) != Some("mined") {
        dump(&state, 1).await;
    }
    assert_eq!(states_of(&state, 1), ["signed", "broadcast", "mined"]);
    assert_eq!(w.balance(&w.tka, &shop).await, 1500);
    // concern C end to end: X's excess deposit came back to the implicit lane (a token → lane transfer) and X still mined
    let t = w.tx(report(&state, 1, "signed")["tx_hash"].as_str().unwrap(), &lane_id(16)).await;
    let back = t["receipts"].as_array().unwrap().iter()
        .any(|r| r["predecessor_id"] == w.tka.as_str() && r["receiver_id"] == lane_id(16).as_str());
    assert!(back, "X's excess deposit refunded to the lane: {:#?}", t["receipts"]);
}
