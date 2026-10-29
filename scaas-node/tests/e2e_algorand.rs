//! smartcontracts/algorand/scripts/e2e.sh   (= scripts/capped devnet.sh algorand up, then
//!   cd scaas-node && ../scripts/capped cargo test -j2 --test e2e_algorand -- --ignored --nocapture; the localnet goes
//!   down on exit, a failure included)
//!
//! near-algorand Task 20 (spec §4.9, §5, §7; R10, R11). Needs the localnet (`devnet.sh algorand up`: algod 4001, kmd 4002,
//! dev mode) and `smartcontracts/scripts/build.sh algorand` (`out/`). The first test deploys with
//! `smartcontracts/scripts/deploy.sh algorand` (funding account = the localnet's KMD dispenser): the account app, the
//! relay-fee router (its off-curve executor salt), tokens TKA and TKB, the mandate and the DEX, every app address funded
//! with its base minimum, the hash gate; then the test-only RelayTarget fixture (the listed third party), lanes funded,
//! TKA / TKB minted to the dispenser (their admin). The tests share that chain, each on its own lane pair with its own fake
//! Odoo (as e2e_aptos.rs). Dev mode makes a block only per transaction group, so a ticker thread sends one every second
//! and the node measures a realistic round time (T17 review note). Proves:
//! 1. the gate fails on an update-accepting approval program and the node halts on it; the deploy resumes after a
//!    partial failure and adopts nothing it did not create with these parameters;
//! 2. every job kind of the node.example.toml algorand row runs to `mined`: plain pay, pay-meta, the relay-fee router to
//!    an account key op, to the listed third party, to a token (invalidate), to the mandate (open / pay / revoke) and to
//!    the DEX (a carried auth); a router job to a failing target dies before submission and costs the lane nothing;
//!    per job kind the node's quote (fee + MBR payments) covers the lane's actual ALGO decrease (QUOTE lines);
//! 3. the GATE items only a real algod shows (GATE lines): simulate refuses an under-fee group, a group short of inner
//!    fee credit, a missing box reference and a wrong MBR payment; the size fee of the largest relay (msig-3 passkey
//!    payer); the box names the node computes are the apps' boxes;
//! 4. the indexer reports PaymentSettled / MetaTransactionExecuted / Transfer rows (joined: meta, relay fee, mandate,
//!    DEX legs), an unregistered token's not.
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Path, State};
use axum::routing::post;
use axum::{Json, Router};
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use scaas_node::adapter::{index_step, lane_step, ChainAdapter, Rejected, Signed};
use scaas_node::adapters::algorand::{
    self as al, abi_bytes, app_address, meta_pay_id, mp_decode, mp_encode, pay_lane, relay_ref, router_call, selector, sha512_256,
    sign_group, Chain, Executor, Group, Holder, MetaOp, Mp, Tx, METAOP_ABI, ORDER_ABI, TERMS_ABI,
};
use scaas_node::addresses::{algorand_address, b32encode};
use scaas_node::config::{ChainCfg, FinalityCfg, OdooCfg, TokenCfg};
use scaas_node::keys::{lane_secret, Seed};
use scaas_node::odoo::{Job, Odoo};
use scaas_node::signer::{LocalSigner, Signer};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const ALGOD: &str = "http://127.0.0.1:4001";
const KMD: &str = "http://127.0.0.1:4002";
/// The env var the node's `params.algod_token_env` names (the localnet's X-Algo-API-Token).
const TOKEN_ENV: &str = "SCAAS_E2E_ALGOD_TOKEN";
const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
/// Lanes 2k, 2k + 1 belong to test k.
const LANES: u32 = 16;
/// µALGO per base unit of TKA / TKB: a fee of `FEE` = 1 ALGO covers any job here.
const PRICE: u64 = 1000;
const FEE: u128 = 1000;
const RP: &str = "pay.scaas.test";
/// test_account.py LONG_ORIGIN / CHROME_CDJ: Chrome's clientDataJSON with its extra key, the T15 worst shape.
const LONG_ORIGIN: &str = "https://checkout.payments.enterprise-wallet.scaas-example.com.vn";
const MBR_AMOUNT_BOX: u64 = 2500 + 400 * (33 + 32);

fn api_token() -> String {
    "a".repeat(64)
}

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

fn u16b(n: usize) -> Vec<u8> {
    (n as u16).to_be_bytes().to_vec()
}

fn u256(n: u128) -> Vec<u8> {
    [vec![0u8; 16], n.to_be_bytes().to_vec()].concat()
}

/// A holder's 33 ARC-4 bytes: kind ‖ id.
fn hb(h: &Holder) -> Vec<u8> {
    [&[h.kind][..], &h.id].concat()
}

fn k(s: &str) -> Mp {
    Mp::str(s)
}

fn int(n: u64) -> Mp {
    Mp::Int(n as i128)
}

/// A msgpack array header for `n` items (signed transactions concatenated after it decode as one array).
fn arr_hdr(n: usize) -> Vec<u8> {
    if n < 16 { vec![0x90 | n as u8] } else { vec![0xdc, 0, n as u8] }
}

// ------------------------------------------------------------------ algod / kmd REST (a client per call: tests run on
// their own runtimes, the world is shared)

async fn http(method: reqwest::Method, url: String, body: Option<(Vec<u8>, &str)>) -> (u16, Value) {
    let c = reqwest::Client::new();
    let mut r = c.request(method, &url).header("X-Algo-API-Token", api_token()).header("X-KMD-API-Token", api_token());
    if let Some((b, ct)) = body {
        r = r.header("Content-Type", ct).body(b);
    }
    let resp = r.send().await.unwrap_or_else(|e| panic!("{url}: {e}"));
    let status = resp.status().as_u16();
    let bytes = resp.bytes().await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or_else(|_| json!({"raw": String::from_utf8_lossy(&bytes)})))
}

async fn get(path: &str) -> Value {
    let (s, v) = http(reqwest::Method::GET, format!("{ALGOD}{path}"), None).await;
    assert!((200..300).contains(&s), "GET {path}: {s} {v}");
    v
}

async fn kmd(path: &str, body: Value) -> Value {
    let (s, v) = http(reqwest::Method::POST, format!("{KMD}{path}"), Some((body.to_string().into_bytes(), "application/json"))).await;
    assert!((200..300).contains(&s), "kmd {path}: {s} {v}");
    v
}

async fn algo(addr: &str) -> u64 {
    get(&format!("/v2/accounts/{addr}?exclude=all")).await["amount"].as_u64().unwrap()
}

async fn box_value(app: u64, name: &[u8]) -> Option<Vec<u8>> {
    let url = reqwest::Url::parse_with_params(&format!("{ALGOD}/v2/applications/{app}/box"), &[("name", format!("b64:{}", b64(name)))]).unwrap();
    let (s, v) = http(reqwest::Method::GET, url.to_string(), None).await;
    match s {
        200 => Some(b64d(v["value"].as_str().unwrap())),
        404 => None,
        _ => panic!("box {app}: {s} {v}"),
    }
}

/// An amount box (`b` ‖ address / `u` ‖ UA id) of a token, as a number.
async fn balance(token: u64, h: &Holder) -> u128 {
    let name = [if h.kind == 0 { &b"b"[..] } else { &b"u"[..] }, &h.id].concat();
    box_value(token, &name).await.map_or(0, |v| u128::from_be_bytes(v[16..32].try_into().unwrap()))
}

struct P {
    min_fee: u64,
    last: u64,
    chain: Chain,
}

async fn params() -> P {
    let v = get("/v2/transactions/params").await;
    P {
        min_fee: v["min-fee"].as_u64().unwrap(),
        last: v["last-round"].as_u64().unwrap(),
        chain: Chain { gen: v["genesis-id"].as_str().unwrap().into(), gh: b64d(v["genesis-hash"].as_str().unwrap()).try_into().unwrap() },
    }
}

/// Distinct LastValid per setup transaction, so two equal setup transactions never share a txid.
static SEQ: AtomicU64 = AtomicU64::new(0);

/// Submits signed bytes and waits until the transaction `txid` (raw 32 bytes) is confirmed: its pending info.
async fn submit_wait(raw: Vec<u8>, txid: &[u8; 32]) -> Result<Value, String> {
    let (s, v) = http(reqwest::Method::POST, format!("{ALGOD}/v2/transactions"), Some((raw, "application/x-binary"))).await;
    if !(200..300).contains(&s) {
        return Err(format!("{s}: {}", v["message"].as_str().unwrap_or(&v.to_string())));
    }
    let id = b32encode(txid);
    for _ in 0..200 {
        let (s, v) = http(reqwest::Method::GET, format!("{ALGOD}/v2/transactions/pending/{id}"), None).await;
        if s == 200 && v["confirmed-round"].as_u64().unwrap_or(0) > 0 {
            return Ok(v);
        }
        if s == 200 && !v["pool-error"].as_str().unwrap_or("").is_empty() {
            return Err(v["pool-error"].to_string());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!("{id} never confirmed"))
}

fn call(app: u64, args: Vec<Vec<u8>>, boxes: Vec<(u64, Vec<u8>)>, apps: Vec<u64>) -> Tx {
    Tx::Call { app, args, accounts: vec![], apps, boxes, executor: false }
}

/// A group of `sk`'s transactions (setup, not the relayer path): fee pooled on the first, one min fee per transaction and
/// per `inner` transaction.
async fn send(sk: &SigningKey, txs: Vec<Tx>, inner: u64) -> Result<Value, String> {
    let p = params().await;
    let fv = p.last;
    let lv = fv + 200 + SEQ.fetch_add(1, Ordering::Relaxed) % 500;
    let g = Group { fee: p.min_fee * (txs.len() as u64 + inner), main: 0, mbr: 0, txs };
    let pk = sk.verifying_key().to_bytes();
    let (raw, ids) = sign_group(&g, &p.chain, fv, lv, &|m: &[u8]| Ok(sk.sign(m).to_bytes().to_vec()), &pk, None).unwrap();
    submit_wait(raw, &ids[0]).await
}

/// The ARC-4 return value of a read-only call, by simulate (as the contract tests' `view`).
async fn query(sk: &SigningKey, app: u64, args: Vec<Vec<u8>>) -> Result<Vec<u8>, String> {
    let p = params().await;
    let g = Group { fee: p.min_fee, main: 0, mbr: 0, txs: vec![call(app, args, vec![], vec![])] };
    let pk = sk.verifying_key().to_bytes();
    let (raw, _) = sign_group(&g, &p.chain, p.last, p.last + 10, &|m: &[u8]| Ok(sk.sign(m).to_bytes().to_vec()), &pk, None).unwrap();
    let req = Mp::Map(vec![(k("txn-groups"), Mp::Arr(vec![Mp::Map(vec![(k("txns"), mp_decode(&[arr_hdr(1), raw].concat()).unwrap())])])),
                           (k("allow-unnamed-resources"), Mp::Bool(true)), (k("extra-opcode-budget"), int(20_000))]);
    let (s, v) = http(reqwest::Method::POST, format!("{ALGOD}/v2/transactions/simulate?format=json"), Some((mp_encode(&req), "application/msgpack"))).await;
    assert_eq!(s, 200, "simulate: {v}");
    let g = &v["txn-groups"][0];
    if let Some(f) = g["failure-message"].as_str().filter(|f| !f.is_empty()) {
        return Err(f.to_string());
    }
    let logs = g["txn-results"][0]["txn-result"]["logs"].as_array().unwrap();
    Ok(b64d(logs.last().unwrap().as_str().unwrap())[4..].to_vec())
}

async fn query_u64(sk: &SigningKey, app: u64, args: Vec<Vec<u8>>) -> u64 {
    u64::from_be_bytes(query(sk, app, args).await.unwrap().try_into().unwrap())
}

/// Simulates `g` exactly as signed by `lane` (every resource named, no extra budget): the group's simulate answer.
async fn simulate(g: &Group, lane: &LocalSigner, exec: Option<&Executor>) -> Value {
    let p = params().await;
    let pk: [u8; 32] = lane.public_key().try_into().unwrap();
    let (raw, _) = sign_group(g, &p.chain, p.last, p.last + 100, &|m: &[u8]| lane.sign(m), &pk, exec).unwrap();
    let req = Mp::Map(vec![(k("txn-groups"), Mp::Arr(vec![Mp::Map(vec![(k("txns"), mp_decode(&[arr_hdr(g.txs.len()), raw].concat()).unwrap())])]))]);
    let (s, v) = http(reqwest::Method::POST, format!("{ALGOD}/v2/transactions/simulate?format=json"), Some((mp_encode(&req), "application/msgpack"))).await;
    assert_eq!(s, 200, "simulate: {v}");
    v["txn-groups"][0].clone()
}

/// An app create (fixtures only: the node never creates apps) by `sk`: its app id.
async fn create_app(sk: &SigningKey, approval: &[u8], clear: &[u8], ints: u64, bytes: u64, args: Vec<Vec<u8>>) -> u64 {
    let p = params().await;
    let snd = sk.verifying_key().to_bytes();
    let mut m = vec![(k("apap"), Mp::Bin(approval.to_vec())), (k("apsu"), Mp::Bin(clear.to_vec())), (k("fee"), int(p.min_fee)),
                     (k("fv"), int(p.last)), (k("gen"), k(&p.chain.gen)), (k("gh"), Mp::Bin(p.chain.gh.to_vec())), (k("lv"), int(p.last + 100)),
                     (k("snd"), Mp::Bin(snd.to_vec())), (k("type"), k("appl"))];
    if !args.is_empty() {
        m.push((k("apaa"), Mp::Arr(args.into_iter().map(Mp::Bin).collect())));
    }
    let mut gs = vec![];
    if bytes > 0 {
        gs.push((k("nbs"), int(bytes)));
    }
    if ints > 0 {
        gs.push((k("nui"), int(ints)));
    }
    if !gs.is_empty() {
        m.push((k("apgs"), Mp::Map(gs)));
    }
    let info = sign_raw(sk, Mp::Map(m)).await.expect("app create");
    info["application-index"].as_u64().unwrap()
}

/// Signs one hand-built transaction map with `sk` and submits it.
async fn sign_raw(sk: &SigningKey, txn: Mp) -> Result<Value, String> {
    let enc = mp_encode(&txn);
    let sig = sk.sign(&[&b"TX"[..], &enc].concat()).to_bytes().to_vec();
    let id = sha512_256(&[&b"TX"[..], &enc[..]]);
    submit_wait(mp_encode(&Mp::Map(vec![(k("sig"), Mp::Bin(sig)), (k("txn"), txn)])), &id).await
}

/// One self-payment of the funding account per second, from its own thread and runtime (dev mode makes a block only per
/// group: without it the node's measured round time would be the deploy's burst, or none).
fn start_ticker(sk: SigningKey) {
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async move {
            let me = sk.verifying_key().to_bytes();
            loop {
                let _ = send(&sk, vec![Tx::Pay { to: me, amount: 0 }], 0).await;
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
    });
}

// ------------------------------------------------------------------ SCaaS signers (account.py tags 0–4)

/// The wallet sign-bytes form: ed25519 over "MX" ‖ "scaas.metaop.v1:" ‖ hex(digest) (ARC-60 style).
fn mx(sk: &SigningKey, d: &[u8; 32]) -> Vec<u8> {
    sk.sign(&[&b"MXscaas.metaop.v1:"[..], hex(d).as_bytes()].concat()).to_bytes().to_vec()
}

fn ua(tag: &str, key_data: &[u8]) -> [u8; 32] {
    keccak(&[&keccak(tag.as_bytes())[..], key_data].concat())
}

trait Who {
    fn h(&self) -> Holder;
    fn auth(&self, d: &[u8; 32]) -> Vec<u8>;
}

/// A native Algorand account (holder kind 0, its 64-byte wallet signature).
struct Nat(SigningKey);

impl Nat {
    fn new(tag: &str) -> Self {
        Nat(SigningKey::from_bytes(&sha(tag.as_bytes())))
    }
    fn pk(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
}

impl Who for Nat {
    fn h(&self) -> Holder {
        Holder::addr(self.pk())
    }
    fn auth(&self, d: &[u8; 32]) -> Vec<u8> {
        mx(&self.0, d)
    }
}

/// An ed25519 UA key (kind 0x0102, tag 1).
struct Ed(SigningKey);

impl Ed {
    fn new(tag: &str) -> Self {
        Ed(SigningKey::from_bytes(&sha(tag.as_bytes())))
    }
}

impl Who for Ed {
    fn h(&self) -> Holder {
        Holder { kind: 1, id: ua("scaas.ua.ed25519.v1", &self.0.verifying_key().to_bytes()) }
    }
    fn auth(&self, d: &[u8; 32]) -> Vec<u8> {
        [&[1u8][..], &self.0.verifying_key().to_bytes(), &mx(&self.0, d)].concat()
    }
}

/// A P-256 passkey of `RP` (kind 0x0100, tag 3) asserting from Chrome with LONG_ORIGIN.
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
}

impl Who for Pk {
    fn h(&self) -> Holder {
        Holder { kind: 1, id: self.id() }
    }
    fn auth(&self, d: &[u8; 32]) -> Vec<u8> {
        let ad = [&sha(RP.as_bytes())[..], &[0x05, 0, 0, 0, 0]].concat();
        let c = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(d);
        let cd = format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"{LONG_ORIGIN}","crossOrigin":false,"other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex"}}"#);
        let sig: p256::ecdsa::Signature = self.0.sign_prehash(&sha(&[&ad[..], &sha(cd.as_bytes())].concat())).unwrap();
        let sig = sig.normalize_s().unwrap_or(sig).to_bytes();
        [&[3u8][..], &self.raw(), &sig[..], &u16b(ad.len()), &ad, cd.as_bytes()].concat()
    }
}

/// An n-of-n msig of passkeys (kind 0x0120, tag 4), members sorted by id.
struct Ms(Vec<Pk>);

impl Ms {
    fn new(seeds: &[u8]) -> Self {
        Ms::of(seeds.iter().map(|s| Pk::new(*s)).collect())
    }
    fn of(mut m: Vec<Pk>) -> Self {
        m.sort_by_key(Pk::id);
        Ms(m)
    }
    fn kd(&self) -> Vec<u8> {
        let rows: Vec<u8> = self.0.iter().flat_map(|p| [&0x0100u16.to_be_bytes()[..], &p.id(), &[0, 1]].concat()).collect();
        [&u16b(self.0.len())[..], &u16b(self.0.len()), &rows].concat()
    }
}

impl Who for Ms {
    fn h(&self) -> Holder {
        Holder { kind: 1, id: ua("scaas.ua.msig.v1", &self.kd()) }
    }
    fn auth(&self, d: &[u8; 32]) -> Vec<u8> {
        let kd = self.kd();
        let mut a = [&[4u8][..], &u16b(kd.len()), &kd].concat();
        for (i, p) in self.0.iter().enumerate() {
            let m = p.auth(d);
            a.push(i as u8);
            a.extend(u16b(m.len()));
            a.extend(m);
        }
        a
    }
}

// ------------------------------------------------------------------ the shared chain

struct World {
    home: PathBuf,
    net: [u8; 32],
    net_b64: String,
    funder: SigningKey,
    account: u64,
    router: u64,
    salt: u8,
    tka: u64,
    tkb: u64,
    mandate: u64,
    dex: u64,
    /// The test-only RelayTarget app: the listed third party (`targets`).
    target: u64,
}

static WORLD: tokio::sync::OnceCell<World> = tokio::sync::OnceCell::const_new();

async fn world() -> &'static World {
    WORLD.get_or_init(start).await
}

fn lane_signer(i: u32) -> LocalSigner {
    let seed = Seed::from_words(MNEMONIC, None).unwrap();
    let (curve, secret) = lane_secret(&seed, "algorand", i).unwrap();
    LocalSigner::new(curve, &secret).unwrap()
}

fn lane_pk(i: u32) -> [u8; 32] {
    lane_signer(i).public_key().try_into().unwrap()
}

fn lane_addr(i: u32) -> String {
    algorand_address(&lane_pk(i))
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

/// The localnet's KMD dispenser (the funded genesis account with the largest balance), as the contract tests' fixture.
async fn dispenser() -> SigningKey {
    let ws = kmd_get("/v1/wallets").await;
    let id = ws["wallets"].as_array().unwrap().iter().find(|w| w["name"] == "unencrypted-default-wallet").unwrap()["id"].clone();
    let h = kmd("/v1/wallet/init", json!({"wallet_id": id, "wallet_password": ""})).await["wallet_handle_token"].clone();
    let addrs = kmd("/v1/key/list", json!({"wallet_handle_token": h})).await["addresses"].as_array().unwrap().clone();
    let mut best = (0, String::new());
    for a in addrs {
        let a = a.as_str().unwrap().to_string();
        let n = algo(&a).await;
        if n > best.0 {
            best = (n, a);
        }
    }
    let sk = b64d(kmd("/v1/key/export", json!({"wallet_handle_token": h, "address": best.1, "wallet_password": ""})).await["private_key"].as_str().unwrap());
    SigningKey::from_bytes(&sk[..32].try_into().unwrap())
}

async fn kmd_get(path: &str) -> Value {
    let (s, v) = http(reqwest::Method::GET, format!("{KMD}{path}"), None).await;
    assert_eq!(s, 200, "kmd {path}: {v}");
    v
}

fn deploy_env(sk: &SigningKey, tokens: &str, dir: &std::path::Path) -> Vec<(&'static str, String)> {
    vec![
        ("ALGORAND_PRIVATE_KEY", b64(&[sk.to_bytes(), sk.verifying_key().to_bytes()].concat())),
        ("ALGOD_TOKEN", api_token()),
        ("ALGORAND_TOKENS", tokens.to_string()),
        ("ALGORAND_DEPLOYMENTS_DIR", dir.to_str().unwrap().to_string()),
    ]
}

/// The URL-safe base64 of the genesis hash: the deployment file's name.
fn gh_file(net_b64: &str) -> String {
    net_b64.replace('+', "-").replace('/', "_")
}

async fn start() -> World {
    std::env::set_var(TOKEN_ENV, api_token());
    let home = std::env::temp_dir().join("scaas-algorand-e2e");
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();
    let funder = dispenser().await;
    start_ticker(funder.clone());
    let p = params().await;
    let net_b64 = b64(&p.chain.gh);
    let dir = home.join("deployments");
    let out = script("smartcontracts/scripts/deploy.sh", &["algorand", ALGOD], &deploy_env(&funder, "TKA:Token A:6,TKB:Token B:6", &dir));
    println!("{}", ok_out("deploy.sh algorand", &out));
    let dep: Value = serde_json::from_str(&std::fs::read_to_string(dir.join(format!("{}.json", gh_file(&net_b64)))).unwrap()).unwrap();
    let n = |k: &str| dep[k].as_u64().unwrap_or_else(|| panic!("deployment {k}: {dep}"));
    let target = {
        let ap = std::fs::read(root().join("smartcontracts/algorand/out/RelayTarget.approval.bin")).unwrap();
        let cl = std::fs::read(root().join("smartcontracts/algorand/out/RelayTarget.clear.bin")).unwrap();
        create_app(&funder, &ap, &cl, 1, 1, vec![selector("create()void").to_vec()]).await
    };
    let w = World {
        home,
        net: p.chain.gh,
        net_b64,
        funder,
        account: n("account"),
        router: n("relayfee"),
        salt: dep["executor"]["salt"].as_u64().unwrap() as u8,
        tka: dep["tokens"][0]["app"].as_u64().unwrap(),
        tkb: dep["tokens"][1]["app"].as_u64().unwrap(),
        mandate: n("mandate"),
        dex: n("dex"),
        target,
    };
    let pays: Vec<Tx> = (0..LANES).map(|i| Tx::Pay { to: lane_pk(i), amount: 20_000_000 }).collect();
    send(&w.funder, pays, 0).await.unwrap();
    let me = w.funder.verifying_key().to_bytes();
    for t in [w.tka, w.tkb] {
        w.mint(t, &me, 1_000_000_000).await;
    }
    w
}

impl World {
    fn me(&self) -> [u8; 32] {
        self.funder.verifying_key().to_bytes()
    }

    fn exec(&self) -> Executor {
        Executor::new(self.router, self.salt).unwrap()
    }

    /// The admin (the funding account) mints to a native address (its balance box paid when new).
    async fn mint(&self, token: u64, to: &[u8; 32], amount: u128) {
        let name = [&b"b"[..], to].concat();
        let mut txs = vec![];
        if box_value(token, &name).await.is_none() {
            txs.push(Tx::Pay { to: app_address(token), amount: MBR_AMOUNT_BOX });
        }
        txs.push(call(token, vec![selector("mint(address,uint256)void").to_vec(), to.to_vec(), u256(amount)], vec![(0, name)], vec![]));
        send(&self.funder, txs, 0).await.unwrap();
    }

    /// The funding account's native `arc200_transfer` / `transfer_to_ua` (outside the relayer: the indexer's Transfer rows).
    async fn transfer(&self, token: u64, to: &Holder, amount: u128) {
        let me = self.me();
        let name = [if to.kind == 0 { &b"b"[..] } else { &b"u"[..] }, &to.id].concat();
        let mut txs = vec![];
        if box_value(token, &name).await.is_none() {
            txs.push(Tx::Pay { to: app_address(token), amount: MBR_AMOUNT_BOX });
        }
        let args = if to.kind == 0 {
            vec![selector("arc200_transfer(address,uint256)bool").to_vec(), to.id.to_vec(), u256(amount)]
        } else {
            vec![selector("transfer_to_ua(byte[32],uint256)void").to_vec(), to.id.to_vec(), u256(amount)]
        };
        txs.push(call(token, args, vec![(0, [&b"b"[..], &me].concat()), (0, name)], vec![]));
        send(&self.funder, txs, 0).await.unwrap();
    }

    /// `who` holds `amount` of `token`: minted (native) or moved to its UA id.
    async fn fund(&self, token: u64, who: &Holder, amount: u128) {
        if who.kind == 0 {
            self.mint(token, &who.id, amount).await;
        } else {
            self.transfer(token, who, amount).await;
        }
    }

    fn op(&self, contract_app: u64, code: u8, from: Holder, to: Holder) -> MetaOp {
        MetaOp { network: self.net, contract: app_address(contract_app), op: code, from, to, relayer: [0; 32], amount: 0, pay_ref: [0; 32],
                 lane: [0; 32], nonce: 0, valid_until: vu(), extra: [0; 32] }
    }

    /// A router job (spec §4.8): `payer` pays `FEE` of TKA in open mode (to = relayer = the router), `pay_ref = ref`,
    /// `lane = payLane(ref)`, nonce 0, `extra = salt`, for `target`'s call `args`; `extra` = more op.extra keys.
    fn relay_job(&self, id: i64, payer: &dyn Who, target: u64, args: &[Vec<u8>], salt: [u8; 32], extra: Value) -> (Value, [u8; 32]) {
        let c = router_call(target, args);
        let r = relay_ref(&self.net, &app_address(target), &c, &salt);
        let ra = app_address(self.router);
        let pay = MetaOp { amount: FEE, pay_ref: r, lane: pay_lane(&r), relayer: ra, extra: salt, ..self.op(self.tka, 0, payer.h(), Holder::addr(ra)) };
        let mut e = json!({"call": hex(&c)});
        for (k, v) in extra.as_object().cloned().unwrap_or_default() {
            e[k] = v;
        }
        (job(id, self.tka, &pay, &payer.auth(&pay.digest()), json!({"kind": "relay_fee", "extra": e})), r)
    }

    /// `verify_mbr` of a signer's first op (0 once its record exists, or for a native wallet signature).
    async fn rec_mbr(&self, who: &dyn Who, d: &[u8; 32], auth: &[u8]) -> u64 {
        let h = who.h();
        if h.kind == 0 && auth.len() == 64 {
            return 0;
        }
        let args = vec![selector("verify_mbr(uint8,byte[32],byte[32],byte[])uint64").to_vec(), vec![h.kind], h.id.to_vec(), d.to_vec(), abi_bytes(auth)];
        query(&self.funder, self.account, args).await.map_or(0, |v| u64::from_be_bytes(v.try_into().unwrap()))
    }

    async fn mbr_needed(&self, token: u64, op: &MetaOp) -> u64 {
        query_u64(&self.funder, token, vec![selector(&format!("mbr_needed({METAOP_ABI})uint64")).to_vec(), op.arc4()]).await
    }

    fn cfg_with(&self, k: u32, tokens: &[u64]) -> ChainCfg {
        let prices: Vec<String> = tokens.iter().map(|t| format!("\"{t}\" = {PRICE}")).collect();
        let t = format!(
            r#"account_app = {}
mandate_app = {}
dex_app = {}
relayfee_app = {}
algod_token_env = "{TOKEN_ENV}"
[relay_fee]
min_amount = 1
min_microalgo_value = {{ {} }}
targets = {{ "{}" = ["ping(uint64)void", "fail()void"] }}
"#,
            self.account, self.mandate, self.dex, self.router, prices.join(", "), self.target
        );
        ChainCfg {
            family: "algorand".into(),
            network: Some(self.net_b64.clone()),
            rpc_urls: vec![ALGOD.into()],
            lanes: vec![2 * k, 2 * k + 1],
            tokens: tokens.iter().map(|t| TokenCfg { address: t.to_string(), decimals: 6 }).collect(),
            params: toml::from_str(&t).unwrap(),
            finality: FinalityCfg { mode: "instant".into(), depth: 0, quorum: 1 },
            poll_ms: 200,
            ..Default::default()
        }
    }

    fn cfg(&self, k: u32) -> ChainCfg {
        self.cfg_with(k, &[self.tka, self.tkb])
    }

    /// Test `k`'s adapter on lanes 2k, 2k + 1 (start-checked).
    async fn adapter(&self, k: u32) -> Arc<dyn ChainAdapter> {
        let a = scaas_node::adapters::build(&self.cfg(k), &[lane_signer(2 * k), lane_signer(2 * k + 1)]).unwrap();
        a.start_check().await.unwrap();
        a
    }
}

/// A `signed_op` job of `op` + `auth` on token app `token`; `extra` = the job kind's fields.
fn job(id: i64, token: u64, op: &MetaOp, auth: &[u8], extra: Value) -> Value {
    let mut o = json!({"family": "algorand", "contract": token.to_string(), "payload": hex(&op.encode()), "signature": hex(auth),
                       "valid_until": op.valid_until});
    for (k, v) in extra.as_object().unwrap() {
        o[k] = v.clone();
    }
    json!({"id": id, "kind": "signed_op", "op": o})
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

/// A fake Odoo registering `tokens`, its cursor at the current round.
async fn odoo(tokens: &[u64]) -> (Odoo, Arc<Mutex<FakeOdoo>>) {
    let state = Arc::new(Mutex::new(FakeOdoo {
        tokens: tokens.iter().map(|t| t.to_string()).collect(),
        indexed_block: params().await.last,
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
        println!("job {id}: {:#?}", state.lock().unwrap().reports.iter().filter(|r| r["job_id"] == id).collect::<Vec<_>>());
    }
    st
}

/// The group the node builds for job `j` on `lane` (its quote: `fee` + `mbr`), by the node's own `build`.
async fn built(a: &dyn ChainAdapter, j: &Value, lane: usize) -> Group {
    let job: Job = serde_json::from_value(j.clone()).unwrap();
    let b = a.build(&job, lane).await.unwrap_or_else(|e| panic!("build job {}: {e:?}", j["id"]));
    serde_json::from_value(b.meta).unwrap()
}

/// Review lesson (a): job `j` runs to `mined` on lane index `li` (address `addr`), and the node's quote for it (the
/// group's pooled fee + its MBR payments, from the node's own build just before) covers the lane's ACTUAL ALGO decrease
/// read from algod across the job. The fee the lane earns is token units (ARC-200), not ALGO: the decrease is net of
/// nothing. Prints a QUOTE line; returns the built group.
#[allow(clippy::too_many_arguments)]
async fn quoted(a: &dyn ChainAdapter, odoo: &Odoo, state: &Arc<Mutex<FakeOdoo>>, li: usize, addr: &str, j: Value, what: &str) -> Group {
    let g = built(a, &j, li).await;
    let before = algo(addr).await;
    assert_eq!(run_job(a, odoo, state, li, j).await, ["signed", "broadcast", "mined"], "{what}");
    let spent = before - algo(addr).await;
    let quote = g.fee + g.mbr;
    let inner = (g.fee / 1000).saturating_sub(g.txs.len() as u64);
    // budget-only: bare, no account / app reference, boxes only empty ones (the node's spec §4.6 calls, review I4)
    let budget_only = g.txs.iter().filter(|t| matches!(t, Tx::Call { args, accounts, apps, boxes, .. }
        if args.is_empty() && accounts.is_empty() && apps.is_empty() && boxes.iter().all(|b| b.1.is_empty()))).count();
    println!("QUOTE {what}: quote {quote} µALGO (fee {} = {} txns + {inner} inner, {budget_only} of them budget-only calls; MBR {}) >= the lane's \
              ALGO decrease {spent}", g.fee, g.txs.len(), g.mbr);
    assert!(quote >= spent, "{what}: the quote {quote} µALGO under-prices the lane's {spent} µALGO decrease");
    g
}

/// Indexes until `done(rows)` (≤ 120 s).
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

/// GATE item (a): real `simulate` refuses each of these mutations of the node's group `g` (the unmutated group passes):
/// under-fee, short of inner fee credit, a missing box reference, a wrong MBR payment. Prints the algod messages.
async fn simulate_refusals(g: &Group, lane: &LocalSigner, exec: Option<&Executor>, min_fee: u64) {
    let ok = simulate(g, lane, exec).await;
    assert!(ok["failure-message"].as_str().unwrap_or("").is_empty(), "the node's own group passes simulate: {ok}");
    let inner = g.fee / min_fee - g.txs.len() as u64;
    assert!(inner > 0, "this group has inner transactions ({})", g.fee);
    let mut under = g.clone();
    under.fee = min_fee * g.txs.len() as u64 - 1;
    let mut credit = g.clone();
    credit.fee -= min_fee;
    let mut nobox = g.clone();
    let dropped = nobox.txs.iter_mut().rev().find_map(|t| match t {
        Tx::Call { boxes, .. } if !boxes.is_empty() => boxes.pop(),
        _ => None,
    });
    assert!(dropped.is_some(), "the group names a box");
    let mut mbr = g.clone();
    let paid = mbr.txs.iter_mut().find_map(|t| match t {
        Tx::Pay { amount, .. } => {
            *amount -= 1;
            Some(*amount + 1)
        }
        _ => None,
    });
    assert!(paid.is_some(), "the group pays an MBR");
    // review M5: each refused for its own reason
    for (what, m, why) in [("under-fee (below one min fee per transaction)", &under, "group fee"),
                           ("short of inner fee credit (one min fee less)", &credit, "inner tx"),
                           ("a box reference missing", &nobox, "invalid Box reference"), ("an MBR payment 1 µALGO short", &mbr, "assert failed")] {
        let s = simulate(m, lane, exec).await;
        let f = s["failure-message"].as_str().unwrap_or("").to_string();
        println!("GATE a {what}: simulate refused: {}", short(&f));
        assert!(f.contains(why) && (why != "group fee" && why != "inner tx" || f.contains("too small")), "{what}: not refused for its reason: {f}");
    }
}

/// A box of `app` named `name` exists (GATE item (d): the node's name layout is the app's).
async fn has_box(app: u64, name: &[u8], what: &str) {
    let v = box_value(app, name).await;
    println!("GATE d box {what} ({} B name) on app {app}: {}", name.len(), if v.is_some() { "present" } else { "MISSING" });
    assert!(v.is_some(), "{what}: no box {} on app {app}", x(name));
}

// ------------------------------------------------------------------ tests

/// R10 / spec §4.9: the deployment passes its own gate (deploy.sh ran it before writing the file); an app whose approval
/// program accepts an update fails it, and the node halts on such an app (`start_check`).
#[tokio::test]
#[ignore]
async fn deploy_gate_fails_on_hash_mismatch() {
    let w = world().await;
    let roles = [format!("account={}", w.account), format!("relayfee={}", w.router), format!("token={}", w.tka), format!("token={}", w.tkb),
                 format!("mandate={}", w.mandate), format!("dex={}", w.dex)];
    let roles: Vec<&str> = roles.iter().map(String::as_str).collect();
    let env = [("ALGOD_TOKEN", api_token())];
    let pass = script("smartcontracts/scripts/deploy.sh", &[&["algorand", ALGOD, "gate"][..], &roles].concat(), &env);
    let log = ok_out("gate", &pass);
    assert!(log.contains("deploy gate: 6 apps match artifacts.json"), "{log}");
    let dep: Value = serde_json::from_str(&std::fs::read_to_string(w.home.join(format!("deployments/{}.json", gh_file(&w.net_b64)))).unwrap()).unwrap();
    assert_eq!(dep["network"], w.net_b64);
    let ex = w.exec();
    assert_eq!(dep["executor"]["address"], algorand_address(&ex.address), "the recorded executor is the node's");
    assert!(!al::on_curve(&ex.address));
    // an approval program that accepts anything, an update included (pushint 1; return)
    let open = [0x0a, 0x81, 0x01, 0x43];
    let bad = create_app(&w.funder, &open, &open, 0, 0, vec![]).await;
    let p = params().await;
    let upd = Mp::Map(vec![(k("apan"), int(4)), (k("apap"), Mp::Bin(open.to_vec())), (k("apid"), int(bad)), (k("apsu"), Mp::Bin(open.to_vec())),
                           (k("fee"), int(p.min_fee)), (k("fv"), int(p.last)), (k("gen"), k(&p.chain.gen)), (k("gh"), Mp::Bin(p.chain.gh.to_vec())),
                           (k("lv"), int(p.last + 100)), (k("snd"), Mp::Bin(w.me().to_vec())), (k("type"), k("appl"))]);
    sign_raw(&w.funder, upd).await.expect("the fixture accepts an update");
    let token = format!("token={bad}");
    let account = format!("account={}", w.account);
    let fail = script("smartcontracts/scripts/deploy.sh", &["algorand", ALGOD, "gate", &account, &token], &env);
    let err = String::from_utf8_lossy(&fail.stderr);
    assert!(!fail.status.success(), "the gate passed an update-accepting app");
    assert!(err.contains("deploy gate FAILED") && err.contains(&format!("token app {bad}")) && err.contains("sha512_256")
        && !err.contains(&format!("account app {}", w.account)), "{err}");
    println!("GATE deploy gate on an update-accepting approval program: {}", err.trim());
    // the node: a configured app with another program halts the chain
    let c = w.cfg_with(0, &[bad]);
    let a = scaas_node::adapters::build(&c, &[lane_signer(0), lane_signer(1)]).unwrap();
    let e = format!("{:#}", a.start_check().await.unwrap_err());
    assert!(e.contains(&format!("token app {bad}")) && e.contains("the chain is halted"), "{e}");
    // the deployed set starts
    let a = w.adapter(0).await;
    assert_eq!(a.chain_key(), format!("algorand:{}", w.net_b64));
    assert_eq!(a.lanes()[0].address, lane_addr(0));
}

/// Review lesson (b): `deploy.sh algorand` checks its env before any chain step; a deploy that fails part way (its
/// funding account cannot hold the next app's MBR) keeps a 0600 resume file; a rerun with another plan is refused (the file kept);
/// the rerun with the original plan resumes, creating nothing twice; a third run creates nothing; an existing token is
/// adopted only with the run's name, symbol, decimals and admin; a deployments directory inside the repository that git
/// does not ignore is refused.
#[tokio::test]
#[ignore]
async fn deploy_resumes_after_an_interruption() {
    use std::os::unix::fs::PermissionsExt;
    let w = world().await;
    let seed = sha(format!("deploy-2 {} {}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()).as_bytes());
    let f = SigningKey::from_bytes(&seed);
    let fa = algorand_address(&f.verifying_key().to_bytes());
    // enough for the account app and the router with their base minimums, not for a token (its 507,000 µALGO of app MBR)
    send(&w.funder, vec![Tx::Pay { to: f.verifying_key().to_bytes(), amount: 900_000 }], 0).await.unwrap();
    let dir = w.home.join("deploy2");
    let env = |tokens: &str, d: &std::path::Path| deploy_env(&f, tokens, d);
    let created = || async {
        let v = get(&format!("/v2/accounts/{fa}")).await;
        v["created-apps"].as_array().cloned().unwrap_or_default().iter().map(|a| {
            let prog = b64d(a["params"]["approval-program"].as_str().unwrap());
            let h = hex(&sha512_256(&[&prog[..]]));
            (a["id"].as_u64().unwrap(), h)
        }).collect::<Vec<_>>()
    };
    let artifacts: Value = serde_json::from_str(&std::fs::read_to_string(root().join("smartcontracts/algorand/artifacts.json")).unwrap()).unwrap();
    let count = |apps: &[(u64, String)], role: &str| apps.iter().filter(|(_, h)| artifacts[role]["approval_sha512_256"] == h.as_str()).count();
    // a malformed token entry: refused before any transaction
    let bad = script("smartcontracts/scripts/deploy.sh", &["algorand", ALGOD], &env("TKA:Token A", &dir));
    assert!(!bad.status.success() && String::from_utf8_lossy(&bad.stderr).contains("ALGORAND_TOKENS"), "{bad:?}");
    assert!(created().await.is_empty(), "nothing deployed");
    // a deployments directory inside the repository that git does not ignore
    let inside = root().join("smartcontracts/algorand/scripts");
    let refused = script("smartcontracts/scripts/deploy.sh", &["algorand", ALGOD], &env("TKA:Token A:6", &inside));
    assert!(!refused.status.success() && String::from_utf8_lossy(&refused.stderr).contains("git does not ignore"), "{refused:?}");
    assert!(created().await.is_empty() && std::fs::read_dir(&inside).unwrap().all(|e| !e.unwrap().file_name().to_string_lossy().contains("resume")));
    // part way: the funding account cannot hold the token's app MBR (algod: "balance … below min …")
    let part = script("smartcontracts/scripts/deploy.sh", &["algorand", ALGOD], &env("TKA:Token A:6", &dir));
    let e = String::from_utf8_lossy(&part.stderr);
    println!("partial deploy: {}{e}", String::from_utf8_lossy(&part.stdout));
    assert!(!part.status.success() && e.contains("below min"), "{e}");
    let resume = dir.join(format!("{}.{fa}.resume.json", gh_file(&w.net_b64)));
    assert_eq!(std::fs::metadata(&resume).expect("resume file kept").permissions().mode() & 0o777, 0o600);
    let r: Value = serde_json::from_str(&std::fs::read_to_string(&resume).unwrap()).unwrap();
    assert!(r["apps"]["account"].is_u64() && r["apps"]["relayfee"].is_u64() && r["pending"]["token:TKA"].is_object(), "{r}");
    let half = created().await;
    // a router that landed off its predicted id with an on-curve executor is recorded as an orphan (the salt race on a
    // chain the other tests keep busy) and created again
    let orphans = r["orphans"].as_array().map_or(0, Vec::len);
    println!("partial deploy: {orphans} orphan router(s) {}", r["orphans"]);
    assert_eq!((count(&half, "account"), count(&half, "relayfee"), count(&half, "token")), (1, 1 + orphans, 0), "{half:?}");
    // review I1: the pending token create was signed with admin = the funding account; a rerun with another admin is
    // refused before any transaction (never resent, never adopted), the resume file kept
    let other_admin = lane_addr(0);
    let mut admin_b = env("TKA:Token A:6", &dir);
    admin_b.push(("ALGORAND_ADMIN", other_admin.clone()));
    let o = script("smartcontracts/scripts/deploy.sh", &["algorand", ALGOD], &admin_b);
    let e = String::from_utf8_lossy(&o.stderr);
    println!("pending create, another admin: {e}");
    assert!(!o.status.success() && e.contains("recorded create") && e.contains(&other_admin) && e.contains("not resent"), "{e}");
    assert!(resume.exists() && created().await.len() == half.len(), "file kept, nothing new deployed");
    // another plan: refused before any transaction, the resume file kept
    let other = script("smartcontracts/scripts/deploy.sh", &["algorand", ALGOD], &env("TKB:Token B:6", &dir));
    let e = String::from_utf8_lossy(&other.stderr);
    assert!(!other.status.success() && e.contains("token:TKA") && e.contains("original"), "{e}");
    assert!(resume.exists() && created().await.len() == half.len(), "file kept, nothing new deployed");
    // topped up, the original plan resumes and finishes
    send(&w.funder, vec![Tx::Pay { to: f.verifying_key().to_bytes(), amount: 5_000_000 }], 0).await.unwrap();
    let out = script("smartcontracts/scripts/deploy.sh", &["algorand", ALGOD], &env("TKA:Token A:6", &dir));
    let log = ok_out("deploy.sh algorand (resumed)", &out);
    println!("{log}");
    assert!(log.contains("resuming") && log.contains("deploy gate: 5 apps match artifacts.json"), "{log}");
    assert!(!resume.exists(), "the resume file is removed after the gate");
    let all = created().await;
    for role in ["account", "token", "mandate", "dex"] {
        assert_eq!(count(&all, role), 1, "{role} created once: {all:?}");
    }
    let dep: Value = serde_json::from_str(&std::fs::read_to_string(dir.join(format!("{}.json", gh_file(&w.net_b64)))).unwrap()).unwrap();
    assert_eq!(dep["account"].as_u64(), r["apps"]["account"].as_u64(), "the resumed account app is the deployment's");
    // a third run: every step already done
    let again = ok_out("deploy.sh algorand (again)", &script("smartcontracts/scripts/deploy.sh", &["algorand", ALGOD], &env("TKA:Token A:6", &dir)));
    assert!(again.contains("adopted") && !again.contains("create ") && again.contains("deploy gate: 5 apps"), "{again}");
    assert_eq!(created().await.len(), all.len());
    // an existing token is not adopted with another name or admin
    let mut admin = env("TKA:Token A:6", &dir);
    admin.push(("ALGORAND_ADMIN", other_admin.clone()));
    for (e, what) in [(env("TKA:Other Name:6", &dir), "Other Name"), (admin, other_admin.as_str())] {
        let o = script("smartcontracts/scripts/deploy.sh", &["algorand", ALGOD], &e);
        let err = String::from_utf8_lossy(&o.stderr);
        assert!(!o.status.success() && err.contains("not adopted") && err.contains(what), "{err}");
    }
    assert_eq!(created().await.len(), all.len());
}

/// A plain `mtx_pay` (native payer) relayed to `mined`; its txid is algod's; a replay is `consumed` (the node's lane box
/// name); an under-fee group is `Rejected` by algod's pool; PaymentSettled + MetaTransactionExecuted indexed.
#[tokio::test]
#[ignore]
async fn algorand_pay_relay_finalize() {
    let w = world().await;
    let a = w.adapter(1).await;
    let (odoo, state) = odoo(&[w.tka]).await;
    let (alice, shop) = (Nat::new("pay-alice"), Nat::new("pay-shop"));
    w.fund(w.tka, &alice.h(), 100_000).await;
    let op = MetaOp { amount: 1000, pay_ref: [0x11; 32], lane: [0xa1; 32], ..w.op(w.tka, 0, alice.h(), shop.h()) };
    let j = job(1, w.tka, &op, &alice.auth(&op.digest()), json!({}));
    let g = quoted(a.as_ref(), &odoo, &state, 0, &lane_addr(2), j.clone(), "mtx_pay (native payer)").await;
    assert_eq!((balance(w.tka, &alice.h()).await, balance(w.tka, &shop.h()).await), (99_000, 1000));
    let hash = report(&state, 1, "signed")["tx_hash"].as_str().unwrap().to_string();
    let t = get(&format!("/v2/transactions/pending/{}", b32encode(&alloy::hex::decode(&hash[2..]).unwrap()))).await;
    assert!(t["confirmed-round"].as_u64().unwrap() > 0 && t["txn"]["txn"]["apid"].as_u64() == Some(w.tka), "own txid = algod's: {t}");
    // the node's box names (GATE d): the payer's lane box, the payee's balance box
    has_box(w.tka, &[&b"l"[..], &sha(&[&hb(&alice.h())[..], &op.lane].concat())].concat(), "lane l ‖ sha256(holder ‖ lane)").await;
    has_box(w.tka, &[&b"b"[..], &shop.pk()].concat(), "balance b ‖ address").await;
    // replay: the payer's lane nonce is spent ⇒ consumed (no fee)
    let mut replay = j;
    replay["id"] = json!(2);
    assert_eq!(run_job(a.as_ref(), &odoo, &state, 0, replay).await, ["consumed"]);
    // an under-fee group: algod's pool refuses it before the pool (Rejected)
    let op3 = MetaOp { amount: 10, pay_ref: [0x13; 32], lane: [0xa3; 32], ..w.op(w.tka, 0, alice.h(), shop.h()) };
    let j3 = job(3, w.tka, &op3, &alice.auth(&op3.digest()), json!({}));
    let mut g3 = built(a.as_ref(), &j3, 0).await;
    g3.fee = 1000 * g3.txs.len() as u64 - 1;
    let p = params().await;
    let lane = lane_signer(2);
    let (raw, ids) = sign_group(&g3, &p.chain, p.last, p.last + 100, &|m: &[u8]| lane.sign(m), &lane_pk(2), None).unwrap();
    let s = Signed { job_id: 3, tx_id: x(&ids[g3.main]), raw, valid_until: op3.valid_until, sequence: p.last };
    let err = a.submit(&s).await.unwrap_err();
    println!("GATE a under-fee group submitted: {}", short(&format!("{err:#}")));
    assert!(err.downcast_ref::<Rejected>().is_some(), "{err:#}");
    let rows = index_until(a.as_ref(), &odoo, &state, |r| !rows_of(r, "PaymentSettled", &[0x11; 32]).is_empty()
        && r.iter().any(|e| e["event"] == "MetaTransactionExecuted" && e["digest"] == x(&op.digest()))).await;
    let ps = rows_of(&rows, "PaymentSettled", &[0x11; 32])[0];
    let tka = w.tka.to_string();
    assert_eq!((ps["contract"].as_str(), ps["from"].as_str(), ps["to"].as_str(), ps["amount"].as_str()),
        (Some(tka.as_str()), Some(algorand_address(&alice.pk()).as_str()), Some(algorand_address(&shop.pk()).as_str()), Some("1000")));
    assert_eq!(ps["tx_hash"], hash);
    assert!(rows.iter().all(|e| e["block_hash"].as_str().unwrap().len() == 66));
    assert!(state.lock().unwrap().refused.is_empty(), "{:#?}", state.lock().unwrap().refused);
    let _ = g;
}

/// CTR-MTX-26 pay-meta by an ed25519 UA payer (its record opened lazily): `pay_ref = metaPayId(salt, meta)`, `lane =
/// payLane`, nonce 0 ⇒ `mtx_pay_meta`, the PaymentSettled row carries `meta`; a pay-meta whose `pay_ref` does not commit to
/// it dies before simulation and costs the lane nothing.
#[tokio::test]
#[ignore]
async fn algorand_pay_meta_job() {
    let w = world().await;
    let a = w.adapter(2).await;
    let (odoo, state) = odoo(&[w.tka]).await;
    let (alice, shop) = (Ed::new("meta-alice"), Nat::new("meta-shop"));
    w.fund(w.tka, &alice.h(), 10_000).await;
    let (salt, meta) = ([0x5a; 32], b"invoice 42 / algorand e2e".to_vec());
    let id = meta_pay_id(&salt, &meta);
    let op = MetaOp { amount: 700, pay_ref: id, lane: pay_lane(&id), ..w.op(w.tka, 0, alice.h(), shop.h()) };
    let kind = json!({"kind": "pay_meta", "salt": hex(&salt), "meta": hex(&meta)});
    let j = job(1, w.tka, &op, &alice.auth(&op.digest()), kind.clone());
    quoted(a.as_ref(), &odoo, &state, 0, &lane_addr(4), j, "mtx_pay_meta (ed25519 UA payer, record opened)").await;
    assert_eq!(balance(w.tka, &shop.h()).await, 700);
    has_box(w.account, &[&b"s"[..], &hb(&alice.h())].concat(), "account record s ‖ kind ‖ id").await;
    let bad = MetaOp { amount: 1, pay_ref: [0x77; 32], lane: pay_lane(&[0x77; 32]), ..w.op(w.tka, 0, alice.h(), shop.h()) };
    let b0 = algo(&lane_addr(5)).await;
    assert_eq!(run_job(a.as_ref(), &odoo, &state, 1, job(2, w.tka, &bad, &alice.auth(&bad.digest()), kind)).await, ["dead"]);
    assert_eq!(algo(&lane_addr(5)).await, b0, "a dead job costs the lane nothing");
    let rows = index_until(a.as_ref(), &odoo, &state, |r| !rows_of(r, "PaymentSettled", &id).is_empty()).await;
    let p = rows_of(&rows, "PaymentSettled", &id)[0];
    assert_eq!((p["meta"].as_str(), p["amount"].as_str(), p["from"].as_str()), (Some(x(&meta).as_str()), Some("700"), Some(x(&alice.h().id).as_str())));
    assert!(rows.iter().all(|e| e["event"] != "PaymentMeta"), "never a row of its own");
}

/// Spec §4.8 router jobs: (i) an account key op (`mtx_add_origin` by an unopened ed25519 UA subject, another UA payer in
/// open mode) — on its group the GATE (a) refusals; (ii) the listed third party (RelayTarget `ping`, its sender the
/// executor, never the lane); (iii) the largest relay: an msig-3 Chrome passkey payer (GATE (b): the size fee); (iv) a
/// token target (`mtx_invalidate_nonces` twice: GATE (d), the `n` box); (v) a target bound to fail (refused, no cost).
#[tokio::test]
#[ignore]
async fn algorand_relay_fee_job() {
    let w = world().await;
    let a = w.adapter(3).await;
    let (odoo, state) = odoo(&[w.tka]).await;
    let ex = w.exec();
    let lane_h = Holder::addr(lane_pk(6));
    // (i) the account app's key op, the subject unopened, the payer another UA
    let (subject, payer) = (Ed::new("wrap-subject"), Ed::new("wrap-payer"));
    w.fund(w.tka, &payer.h(), 10_000).await;
    let origin = b"https://app.scaas.test".to_vec();
    let eop = MetaOp { extra: sha(&[&[0u8, 2][..], &abi_bytes(&origin)].concat()), ..w.op(w.account, 8, subject.h(), subject.h()) };
    let args = vec![selector(&format!("mtx_add_origin({METAOP_ABI},byte[],byte[])void")).to_vec(), eop.arc4(), abi_bytes(&subject.auth(&eop.digest())),
                    abi_bytes(&origin)];
    let (j, r1) = w.relay_job(1, &payer, w.account, &args, [0x5b; 32], json!({}));
    let g = built(a.as_ref(), &j, 0).await;
    simulate_refusals(&g, &lane_signer(6), Some(&ex), params().await.min_fee).await;
    let l0 = balance(w.tka, &lane_h).await;
    quoted(a.as_ref(), &odoo, &state, 0, &lane_addr(6), j, "router -> account.mtx_add_origin (ed25519 UA subject opened, UA payer)").await;
    assert_eq!(balance(w.tka, &lane_h).await - l0, FEE, "open mode: the fee reaches the submitting lane");
    assert_eq!(balance(w.tka, &payer.h()).await, 10_000 - FEE);
    has_box(w.account, &[&b"s"[..], &hb(&subject.h())].concat(), "the subject's record s ‖ kind ‖ id").await;
    let node = al::AlgorandAdapter::new(&w.cfg(3), &[lane_signer(6), lane_signer(7)]).unwrap();
    let sets = node.key_sets(&subject.h()).await.unwrap();
    println!("GATE d key_sets(subject) = {sets:?}");
    assert!(sets.iter().all(|(_, k)| k.as_ref().is_some_and(|k| k.len() == 1)), "the node reads the record by its name: {sets:?}");
    // (ii) the listed third party: its sender is the executor
    let pp = Nat::new("ping-payer");
    w.fund(w.tka, &pp.h(), 10_000).await;
    let (j, r2) = w.relay_job(2, &pp, w.target, &[selector("ping(uint64)void").to_vec(), 7u64.to_be_bytes().to_vec()], [0x5c; 32], json!({}));
    quoted(a.as_ref(), &odoo, &state, 0, &lane_addr(6), j, "router -> listed third party RelayTarget.ping (native payer)").await;
    let gs = get(&format!("/v2/applications/{}", w.target)).await;
    let last = gs["params"]["global-state"].as_array().unwrap().iter().find(|g| g["key"] == b64(b"last")).unwrap()["value"]["bytes"].clone();
    assert_eq!(b64d(last.as_str().unwrap()), ex.address, "the target's sender is the executor, never the lane");
    // (iii) the largest relay: an msig-3 Chrome passkey payer (its record opened by this relay)
    let ms = Ms::new(&[31, 32, 33]);
    w.fund(w.tka, &ms.h(), 10_000).await;
    let (j, r3) = w.relay_job(3, &ms, w.target, &[selector("ping(uint64)void").to_vec(), 9u64.to_be_bytes().to_vec()], [0x5d; 32], json!({}));
    let auth_len = hex_len(&j["op"]["signature"]);
    // review I4: T15's absolute worst (msig is capped at 3 members on Algorand): an msig-3 Chrome subject's key op (its
    // record opened) paid by another msig-3 Chrome payer (its record opened too)
    let (subj3, pay3) = (Ms::new(&[61, 62, 63]), Ms::new(&[64, 65, 66]));
    w.fund(w.tka, &pay3.h(), 10_000).await;
    let none = [0u8; 33];
    let gop = MetaOp { extra: sha(&none), ..w.op(w.account, 10, subj3.h(), subj3.h()) };
    let gargs = vec![selector(&format!("mtx_set_guardian({METAOP_ABI},byte[],(uint8,byte[32]))void")).to_vec(), gop.arc4(),
                     abi_bytes(&subj3.auth(&gop.digest())), none.to_vec()];
    let (j5, r5) = w.relay_job(7, &pay3, w.account, &gargs, [0x5a; 32], json!({}));
    quoted(a.as_ref(), &odoo, &state, 0, &lane_addr(6), j5, "router -> account.mtx_set_guardian (msig-3 Chrome subject + msig-3 Chrome payer)").await;
    let g = quoted(a.as_ref(), &odoo, &state, 1, &lane_addr(7), j, "router -> RelayTarget.ping (msig-3 Chrome passkey payer)").await;
    let p = params().await;
    let relay_args: usize = g.txs.iter().find_map(|t| match t {
        Tx::Call { app, args, .. } if *app == w.router => Some(args.iter().map(Vec::len).sum()),
        _ => None,
    }).unwrap();
    let mut less = g.clone();
    less.fee -= 1;
    let s = simulate(&less, &lane_signer(7), Some(&ex)).await;
    let f = s["failure-message"].as_str().unwrap_or("").to_string();
    println!("GATE b size fee: relay args {relay_args} B (payer auth {auth_len} B), {} txns, network fee per byte {} (algod `fee`), min fee {}: \
              the node quoted fee {} µALGO, algod charged it and accepts nothing less (fee - 1: {})",
             g.txs.len(), get("/v2/transactions/params").await["fee"], p.min_fee, g.fee, short(&f));
    assert!(!f.is_empty(), "a fee 1 µALGO below the node's passes: the node over-prices");
    // (iv) a token as the target: mtx_invalidate_nonces twice; the second runs only if the node finds the min_nonce box
    // ("n" ‖ sha256(holder ‖ lane)) the first created, by its name (else its MBR payment would be 18,900 too high)
    let sub = Nat::new("inv-subject");
    let tl = [0xd1; 32];
    for (n, jid, salt) in [(5u64, 4i64, [0x5e; 32]), (9, 5, [0x5f; 32])] {
        let params = [&tl[..], &n.to_be_bytes()].concat();
        let iop = MetaOp { extra: sha(&params), ..w.op(w.tka, 15, sub.h(), sub.h()) };
        let args = vec![selector(&format!("mtx_invalidate_nonces({METAOP_ABI},byte[],byte[32],uint64)void")).to_vec(), iop.arc4(),
                        abi_bytes(&sub.auth(&iop.digest())), tl.to_vec(), n.to_be_bytes().to_vec()];
        let (j, _) = w.relay_job(jid, &pp, w.tka, &args, salt, json!({}));
        let what = format!("router -> token.mtx_invalidate_nonces (native subject, min_nonce {n}{})", if n == 5 { ", box new" } else { ", box exists" });
        quoted(a.as_ref(), &odoo, &state, 0, &lane_addr(6), j, &what).await;
    }
    let nbox = [&b"n"[..], &sha(&[&hb(&sub.h())[..], &tl].concat())].concat();
    has_box(w.tka, &nbox, "min_nonce n ‖ sha256(holder ‖ lane)").await;
    assert_eq!(box_value(w.tka, &nbox).await.unwrap(), 9u64.to_be_bytes().to_vec());
    // (v) a listed target whose call fails: refused by simulate, never sent, the lane pays nothing (lessons 15 / 16)
    let (j, _) = w.relay_job(6, &pp, w.target, &[selector("fail()void").to_vec()], [0x60; 32], json!({}));
    let b0 = algo(&lane_addr(7)).await;
    assert_eq!(run_job(a.as_ref(), &odoo, &state, 1, j).await, ["dead"]);
    assert_eq!(algo(&lane_addr(7)).await, b0, "a group bound to fail costs the lane nothing");
    let rows = index_until(a.as_ref(), &odoo, &state, |rows| [r1, r2, r3, r5].iter().all(|r| rows_of(rows, "PaymentSettled", r).iter().any(|p| p["relay_payee"].is_string()))).await;
    for (r, lane) in [(r1, 6), (r2, 6), (r3, 7)] {
        let p = rows_of(&rows, "PaymentSettled", &r)[0];
        assert_eq!((p["relay_payee"].as_str(), p["to"].as_str()), (Some(lane_addr(lane).as_str()), Some(lane_addr(lane).as_str())), "{p}");
    }
    assert!(rows.iter().all(|e| e["event"] != "RelayFeePaid"), "joined into PaymentSettled");
    assert!(state.lock().unwrap().refused.is_empty(), "{:#?}", state.lock().unwrap().refused);
}

/// algod's refusals embed Go struct dumps: the reason is at the start.
fn short(s: &str) -> String {
    s.chars().take(320).collect()
}

fn hex_len(v: &Value) -> usize {
    v.as_str().unwrap().len() / 2
}

/// The mandate through the router (open by a native owner with its funding op, pay by an ed25519 UA delegate, revoke by
/// the owner); the pay is indexed as the token's PaymentSettled from `0x` ‖ mandate id.
#[tokio::test]
#[ignore]
async fn algorand_router_mandate() {
    let w = world().await;
    let a = w.adapter(4).await;
    let (odoo, state) = odoo(&[w.tka]).await;
    let (owner, delegate, payee, payer) = (Nat::new("man-owner"), Ed::new("man-delegate"), Nat::new("man-payee"), Nat::new("man-payer"));
    w.fund(w.tka, &owner.h(), 10_000).await;
    w.fund(w.tka, &payer.h(), 10_000).await;
    let tka = w.tka.to_be_bytes().to_vec();
    let mapp = app_address(w.mandate);
    let terms = [hb(&delegate.h()), hb(&payee.h()), 100u128.to_be_bytes().to_vec(), 250u128.to_be_bytes().to_vec(), 3_600u64.to_be_bytes().to_vec(),
                 vu().to_be_bytes().to_vec(), 1_000u128.to_be_bytes().to_vec()].concat();
    let mlane = [0xb0; 32];
    let id = sha(&[hb(&owner.h()), terms.clone(), mlane.to_vec(), 0u64.to_be_bytes().to_vec()].concat());
    let fop = MetaOp { amount: 1_000, pay_ref: id, lane: mlane, relayer: mapp, extra: sha(&[&tka[..], &id, &terms].concat()),
                       ..w.op(w.tka, 0, owner.h(), Holder::addr(mapp)) };
    let fund_mbr = w.mbr_needed(w.tka, &fop).await;
    let open = vec![selector(&format!("mtx_mandate_open(uint64,{METAOP_ABI},byte[],{TERMS_ABI},uint64)void")).to_vec(), tka.clone(), fop.arc4(),
                    abi_bytes(&owner.auth(&fop.digest())), terms, fund_mbr.to_be_bytes().to_vec()];
    let (j, _) = w.relay_job(1, &payer, w.mandate, &open, [0x61; 32], json!({}));
    quoted(a.as_ref(), &odoo, &state, 0, &lane_addr(8), j, "router -> mandate.mtx_mandate_open (native owner)").await;
    let mid = Holder { kind: 1, id };
    assert_eq!((balance(w.tka, &Holder::addr(mapp)).await, balance(w.tka, &owner.h()).await), (1_000, 9_000), "the mandate funded");
    has_box(w.mandate, &[&b"m"[..], &tka, &id].concat(), "mandate m ‖ token ‖ id").await;
    let pr = [0x71; 32];
    let pop = MetaOp { amount: 100, pay_ref: pr, lane: pay_lane(&pr), extra: sha(&tka), ..w.op(w.mandate, 2, mid, payee.h()) };
    let pay = vec![selector(&format!("mtx_mandate_pay(uint64,{METAOP_ABI},byte[])void")).to_vec(), tka.clone(), pop.arc4(), abi_bytes(&delegate.auth(&pop.digest()))];
    let (j, _) = w.relay_job(2, &payer, w.mandate, &pay, [0x62; 32], json!({}));
    quoted(a.as_ref(), &odoo, &state, 0, &lane_addr(8), j, "router -> mandate.mtx_mandate_pay (ed25519 UA delegate, record opened)").await;
    assert_eq!(balance(w.tka, &payee.h()).await, 100);
    let rop = MetaOp { extra: sha(&tka), ..w.op(w.mandate, 3, owner.h(), mid) };
    let revoke = vec![selector(&format!("mtx_revoke(uint64,{METAOP_ABI},byte[])void")).to_vec(), tka.clone(), rop.arc4(), abi_bytes(&owner.auth(&rop.digest()))];
    let (j, _) = w.relay_job(3, &payer, w.mandate, &revoke, [0x63; 32], json!({}));
    quoted(a.as_ref(), &odoo, &state, 1, &lane_addr(9), j, "router -> mandate.mtx_revoke (native owner)").await;
    assert_eq!((balance(w.tka, &owner.h()).await, balance(w.tka, &Holder::addr(mapp)).await), (9_900, 0), "the rest back to the owner");
    let rows = index_until(a.as_ref(), &odoo, &state, |r| !rows_of(r, "PaymentSettled", &pr).is_empty()).await;
    let p = rows_of(&rows, "PaymentSettled", &pr)[0];
    let tka_s = w.tka.to_string();
    assert_eq!((p["contract"].as_str(), p["from"].as_str(), p["to"].as_str(), p["amount"].as_str()),
        (Some(tka_s.as_str()), Some(x(&id).as_str()), Some(algorand_address(&payee.pk()).as_str()), Some("100")));
    assert!(state.lock().unwrap().refused.is_empty(), "{:#?}", state.lock().unwrap().refused);
}

/// A DEX settle through the router: two crossing orders (TKA → TKB bound to the submitting lane, TKB → TKA open), leg a
/// signed by an msig-3 Chrome passkey seller and carried (`carry`, op.extra.carries), leg b by a native seller; both legs
/// paid out, the fee to the lane, the trade rows carry `leg_digest` and `settle_id`.
#[tokio::test]
#[ignore]
async fn algorand_router_dex_settle() {
    let w = world().await;
    let a = w.adapter(5).await;
    let (odoo, state) = odoo(&[w.tka, w.tkb]).await;
    let (sa, sb, payer) = (Ms::new(&[41, 42, 43]), Nat::new("dex-sb"), Nat::new("dex-payer"));
    w.fund(w.tka, &sa.h(), 500).await;
    w.fund(w.tkb, &sb.h(), 300).await;
    w.fund(w.tka, &payer.h(), 10_000).await;
    let dexa = app_address(w.dex);
    let order = |sell: u64, buy: u64, n: u128, min: u128, relayer: [u8; 32]| {
        [sell.to_be_bytes().to_vec(), buy.to_be_bytes().to_vec(), n.to_be_bytes().to_vec(), min.to_be_bytes().to_vec(), relayer.to_vec(),
         vu().to_be_bytes().to_vec()].concat()
    };
    let (oa, ob) = (order(w.tka, w.tkb, 500, 300, lane_pk(10)), order(w.tkb, w.tka, 300, 500, [0; 32]));
    let leg = |token: u64, who: &dyn Who, n: u128, o: &[u8], lane: u8| MetaOp {
        amount: n, lane: [lane; 32], relayer: dexa, extra: sha(o), ..w.op(token, 1, who.h(), Holder::addr(dexa))
    };
    let (opa, opb) = (leg(w.tka, &sa, 500, &oa, 0xc1), leg(w.tkb, &sb, 300, &ob, 0xc2));
    let (aa, ab) = (sa.auth(&opa.digest()), sb.auth(&opb.digest()));
    let payout = |t: u64, h: Holder| async move { if balance(t, &h).await == 0 { MBR_AMOUNT_BOX } else { 0 } };
    let mbr = [w.mbr_needed(w.tka, &opa).await + w.rec_mbr(&sa, &opa.digest(), &aa).await, w.mbr_needed(w.tkb, &opb).await,
               payout(w.tka, sb.h()).await, payout(w.tkb, sa.h()).await];
    let settle = vec![selector(&format!("settle({ORDER_ABI},{METAOP_ABI},byte[],{ORDER_ABI},{METAOP_ABI},byte[],uint64[4])void")).to_vec(),
                      oa, opa.arc4(), abi_bytes(&[]), ob, opb.arc4(), abi_bytes(&ab), mbr.iter().flat_map(|m| m.to_be_bytes()).collect()];
    let (j, r) = w.relay_job(1, &payer, w.dex, &settle, [0x6a; 32], json!({"carries": [hex(&aa)]}));
    let lane_h = Holder::addr(lane_pk(10));
    let l0 = balance(w.tka, &lane_h).await;
    let g = quoted(a.as_ref(), &odoo, &state, 0, &lane_addr(10), j, "router -> dex.settle (msig-3 passkey leg carried, native leg)").await;
    println!("DEX settle group: {} txns, MBR parts {mbr:?}, carry auth {} B", g.txs.len(), aa.len());
    assert_eq!((balance(w.tkb, &sa.h()).await, balance(w.tka, &sb.h()).await), (300, 500), "both legs paid out");
    assert_eq!((balance(w.tka, &sa.h()).await, balance(w.tkb, &sb.h()).await), (0, 0));
    assert_eq!(balance(w.tka, &lane_h).await - l0, FEE, "open mode: the router pays the relaying lane");
    let rows = index_until(a.as_ref(), &odoo, &state, |rows| rows_of(rows, "PaymentSettled", &r).iter().any(|p| p["relay_payee"].is_string())
        && rows.iter().filter(|e| e["event"] == "Transfer" && e["settle_id"].is_string()).count() >= 2).await;
    let trades: Vec<&Value> = rows.iter().filter(|e| e["event"] == "Transfer" && e["settle_id"].is_string()).collect();
    let (ta, tb) = (w.tka.to_string(), w.tkb.to_string());
    assert!(trades.iter().any(|t| t["contract"] == ta.as_str()) && trades.iter().any(|t| t["contract"] == tb.as_str()), "{trades:#?}");
    assert!(trades.iter().all(|t| t["leg_digest"].is_string()));
    assert!(state.lock().unwrap().refused.is_empty(), "{:#?}", state.lock().unwrap().refused);
}

/// ARC-200 moves outside the relayer: a native `arc200_transfer` and a `transfer_to_ua` of the funding account are indexed
/// as Transfer rows; the same on a token Odoo has not registered (TKB) is not.
#[tokio::test]
#[ignore]
async fn algorand_events_ingested() {
    let w = world().await;
    let a = w.adapter(6).await;
    let (odoo, state) = odoo(&[w.tka]).await;
    let to = Nat::new("native-to");
    w.transfer(w.tka, &to.h(), 77).await;
    w.transfer(w.tkb, &to.h(), 88).await;
    let u = Ed::new("native-ua").h();
    w.transfer(w.tka, &u, 99).await;
    let (to_s, u_s, me) = (algorand_address(&to.pk()), x(&u.id), algorand_address(&w.me()));
    let rows = index_until(a.as_ref(), &odoo, &state, |rows| {
        rows.iter().any(|e| e["event"] == "Transfer" && e["to"] == to_s.as_str() && e["amount"] == "77")
            && rows.iter().any(|e| e["event"] == "Transfer" && e["to"] == u_s.as_str())
    }).await;
    let t = rows.iter().find(|e| e["event"] == "Transfer" && e["to"] == to_s.as_str() && e["amount"] == "77").unwrap();
    let tka = w.tka.to_string();
    assert_eq!((t["from"].as_str(), t["contract"].as_str()), (Some(me.as_str()), Some(tka.as_str())));
    let ua_row = rows.iter().find(|e| e["event"] == "Transfer" && e["to"] == u_s.as_str()).unwrap();
    assert_eq!((ua_row["from"].as_str(), ua_row["amount"].as_str()), (Some(me.as_str()), Some("99")));
    let tkb = w.tkb.to_string();
    assert!(rows.iter().all(|e| e["contract"] != tkb.as_str() && e["amount"] != "88"), "an unregistered token is not indexed");
    // T17 review note: the round time the node measures (two block timestamps 100 rounds apart, the ticker driving blocks)
    let last = params().await.last;
    let ts = |r: u64| async move {
        let (_, v) = http(reqwest::Method::GET, format!("{ALGOD}/v2/blocks/{r}"), None).await;
        v["block"]["ts"].as_u64().unwrap()
    };
    let (t1, t0) = (ts(last).await, ts(last.saturating_sub(100).max(1)).await);
    println!("ROUNDS {} rounds in {} s up to round {last} (dev mode: one block per group, the ticker one per second)", last - last.saturating_sub(100).max(1), t1 - t0);
    assert!(state.lock().unwrap().refused.is_empty(), "{:#?}", state.lock().unwrap().refused);
}
