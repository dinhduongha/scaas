//! UA-Soroban local e2e (spec §10, S17; plan T10): `smartcontracts/soroban/scripts/e2e-local.sh`, or by hand with a
//! running quickstart: `cargo test --test e2e_soroban_ua -- --ignored --test-threads=1 --nocapture` (env: see
//! `soroban_common`; T14 runs it against the Stellar testnet).
//!
//! One stack per run, deployed through `smartcontracts/scripts/deploy.sh soroban` (`relay_fee` = the executor and the
//! router): the registry (relayers = the two lanes), two tokens bound to it, the relay-fee router, a mandate owned by a
//! native account and the DEX. A passkey (`webauthn-p256`) UA and an `mldsa65` UA are registered by lane 0 through the
//! CLI (anyone may submit; the node's `call` job is Part B's). UA signatures come from
//! `clients/clientkeys/scripts/soroban-sign.mjs` (SOR-D13); UA entries go through the node as `ua_metatx` jobs
//! (`lane_step`), and their rows through `index_step`. Every transaction logs its CPU instructions and fees.
mod soroban_common;

use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use scaas_node::adapter::{index_step, lane_step, ChainAdapter};
use scaas_node::adapters::soroban::{holder_addr, op_digest, relay_ref, SorobanAdapter};
use scaas_node::config::TokenCfg;
use scaas_node::odoo::Odoo;
use scaas_node::signer::Signer;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use soroban_common::*;
use stellar_xdr::{
    Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization, Int128Parts, InvokeContractArgs, Limits, ScAddress, ScMap,
    ScMapEntry, ScSymbol, ScVal, ScVec, SorobanAuthorizedFunction, SorobanAuthorizedInvocation, WriteXdr,
};
use tokio::sync::OnceCell;

const OPS: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../smartcontracts/soroban/vectors/ua-ops.json"));
const SIGNER: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../clients/clientkeys/scripts/soroban-sign.mjs");
/// Account indexes of the test mnemonic (`soroban_common::key`): lanes 0 and 1, the deployer (admin, mandate owner,
/// native payer), the DEX's native taker, and a bystander.
const DEPLOYER: u32 = 7;
const TAKER: u32 = 9;
const BYSTANDER: u32 = 8;
/// Empty `Bytes` for the CLI: the JSON string `""` (a bare empty value is refused as missing).
const EMPTY_PQZ_POP: &str = "--pqz_pop=\"\"";
const EMPTY_AUTH: &str = "--auth=\"\"";

/// A UA test signer: the `soroban-sign.mjs` kind and key index, and its `ua-ops.json` registration row.
#[derive(Clone, Copy)]
struct UaKey {
    kind: &'static str,
    index: u32,
    row: &'static str,
}
const PASSKEY: UaKey = UaKey { kind: "webauthn-p256", index: 0, row: "webauthn-p256" };
const MLDSA65: UaKey = UaKey { kind: "mldsa65", index: 2, row: "mldsa65#2" };

impl UaKey {
    fn registration(&self) -> Value {
        let ops: Value = serde_json::from_str(OPS).unwrap();
        ops["registrations"].as_array().unwrap().iter().find(|r| r["name"] == self.row).cloned().unwrap()
    }
    fn id(&self) -> [u8; 32] {
        unhex(self.registration()["ua"].as_str().unwrap()).try_into().unwrap()
    }
    /// `auth` for (`digest`, `purpose`) by the clientkeys e2e signer.
    fn sign(&self, digest: &[u8; 32], purpose: &str) -> ScVal {
        let out = Command::new("node").args([SIGNER, self.kind, &self.index.to_string(), &hx(digest), purpose]).output().expect("node");
        assert!(out.status.success(), "soroban-sign.mjs: {}", String::from_utf8_lossy(&out.stderr));
        let v: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(v["ua"].as_str().unwrap(), format!("0x{}", hx(&self.id())), "{} signs as another UA", self.row);
        bytes(&unhex(v["auth"].as_str().unwrap()))
    }
}

fn hx(b: &[u8]) -> String {
    alloy::hex::encode(b)
}

fn unhex(s: &str) -> Vec<u8> {
    alloy::hex::decode(s).unwrap()
}

/// A fresh 32-byte value (pay refs, salts): a run never reuses one.
fn fresh() -> [u8; 32] {
    static N: AtomicU64 = AtomicU64::new(0);
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    Sha256::digest(format!("{t}/{}", N.fetch_add(1, Ordering::Relaxed))).into()
}

fn sc(s: &str) -> ScAddress {
    s.parse().unwrap()
}
fn bytes(b: &[u8]) -> ScVal {
    ScVal::Bytes(b.to_vec().try_into().unwrap())
}
fn i128v(n: i128) -> ScVal {
    ScVal::I128(Int128Parts { hi: (n >> 64) as i64, lo: n as u64 })
}
fn sym(s: &str) -> ScSymbol {
    ScSymbol(s.try_into().unwrap())
}
fn vecv(v: Vec<ScVal>) -> ScVal {
    ScVal::Vec(Some(ScVec(v.try_into().unwrap())))
}
fn h_ua(u: &[u8; 32]) -> ScVal {
    vecv(vec![ScVal::Symbol(sym("Ua")), bytes(u)])
}
fn h_addr(s: &str) -> ScVal {
    holder_addr(&sc(s))
}
/// CLI JSON of a `Holder`.
fn ua_json(u: &[u8; 32]) -> String {
    format!("{{\"Ua\":\"{}\"}}", hx(u))
}

/// A DEX `Order` as its contracttype map (fields sorted).
#[allow(clippy::too_many_arguments)]
fn order(maker: ScVal, destination: ScVal, relayer: &str, sell: &str, sell_amount: i128, buy: &str, buy_amount: i128, expiry: u64, salt: u64) -> ScVal {
    let e = |k: &str, v: ScVal| ScMapEntry { key: ScVal::Symbol(sym(k)), val: v };
    ScVal::Map(Some(ScMap(
        vec![
            e("buy_amount", i128v(buy_amount)), e("buy_token", addr(buy)), e("destination", destination), e("expiry", ScVal::U64(expiry)),
            e("maker", maker), e("max_fee_ppm", ScVal::U32(0)), e("relayer", addr(relayer)), e("salt", ScVal::U64(salt)),
            e("sell_amount", i128v(sell_amount)), e("sell_token", addr(sell)),
        ]
        .try_into()
        .unwrap(),
    )))
}

/// The op digest a UA signs (NET-SOR-16): the entry's arguments without `auth`.
fn digest(contract: &str, f: &str, args: &[ScVal]) -> [u8; 32] {
    op_digest(&network(), &sc(contract), &sym(f), args).unwrap()
}

/// SOR-D14's job: `{kind: "ua_metatx", op: {contract, function, args: hex XDR ScVec (auth included), auth?}}`.
fn ua_job(id: i64, contract: &str, function: &str, args: Vec<ScVal>, auth: Vec<Value>) -> Value {
    let a = ScVec(args.try_into().unwrap()).to_xdr(Limits::none()).unwrap();
    let mut op = json!({"contract": contract, "function": function, "args": format!("0x{}", hx(&a))});
    if !auth.is_empty() {
        op["auth"] = json!(auth);
    }
    json!({"id": id, "kind": "ua_metatx", "op": op})
}

/// `stellar contract invoke --id <id> --source-account <src> -- <f> <args…>`: a view (simulated, never sent).
fn view(id: &str, f: &str, args: &[&str]) -> String {
    let src = secret(DEPLOYER);
    let mut a = vec!["contract", "invoke", "--id", id, "--source-account", &src, "--send", "no", "--", f];
    a.extend_from_slice(args);
    cli(&a).trim_matches('"').to_string()
}

fn view_i128(id: &str, f: &str, args: &[&str]) -> i128 {
    view(id, f, args).parse().unwrap()
}

/// A state-changing invoke by account `src`; logs its cost.
async fn send(what: &str, src: u32, id: &str, f: &str, args: &[&str]) -> String {
    let s = secret(src);
    let mut a = vec!["contract", "invoke", "--id", id, "--source-account", &s, "--", f];
    a.extend_from_slice(args);
    let (out, hash) = cli_tx(&a);
    log_cost(what, &hash).await;
    out.trim_matches('"').to_string()
}

struct Registered {
    key: UaKey,
    id: [u8; 32],
    tx: String,
    cost: Cost,
}

struct Stack {
    registry: String,
    token: String,
    token_b: String,
    router: String,
    executor: String,
    mandate: String,
    dex: String,
    registered: Vec<Registered>,
}

static STACK: OnceCell<Stack> = OnceCell::const_new();

async fn stack() -> &'static Stack {
    STACK.get_or_init(setup).await
}

/// Deploys the stack through `deploy.sh` and registers the two UAs (lane 0 submits through the CLI).
async fn setup() -> Stack {
    for i in [0, 1, DEPLOYER, TAKER] {
        fund(&g(&key(i))).await;
    }
    let (s, admin) = (secret(DEPLOYER), g(&key(DEPLOYER)));
    let relayers = format!("[\"{}\",\"{}\"]", g(&key(0)), g(&key(1)));
    let registry = deploy_sh("ua_registry", &s, &["--relayers", &relayers]);
    // an `Option<Address>` constructor argument is JSON: the quoted strkey
    let reg = format!("\"{registry}\"");
    let tok = |symbol: &str| deploy_sh("token", &s, &["--admin", &admin, "--decimals", "7", "--name", "SCaaS", "--symbol", symbol, "--registry", &reg]);
    let (token, token_b) = (tok("BMB"), tok("BMBB"));
    let router = deploy_sh("relay_fee", &s, &[]);
    let executor = view(&router, "executor", &[]);
    assert_eq!(view(&executor, "router", &[]), router, "the executor is bound to the router");
    let mandate = deploy_sh("mandate", &s, &["--owner", &format!("{{\"Addr\":\"{admin}\"}}"), "--registry", &reg]);
    let dex = deploy_sh("dex", &s, &["--admin", &admin, "--fee_recipient", &admin, "--registry", &reg]);
    println!("T10 stack: registry {registry} token {token} token_b {token_b} router {router} executor {executor} mandate {mandate} dex {dex}");

    let attrs = format!("{{\"kem_pk\":\"\",\"kem_version\":0,\"pqz_key\":\"\",\"pqz_pop_hash\":\"{}\"}}", "0".repeat(64));
    let mut registered = Vec::new();
    for k in [PASSKEY, MLDSA65] {
        let r = k.registration();
        let (kind, key_data, pop) = (r["kind"].to_string(), r["keyData"].as_str().unwrap().trim_start_matches("0x"), r["pop"].as_str().unwrap().trim_start_matches("0x"));
        let l0 = secret(0);
        let (out, tx) = cli_tx(&["contract", "invoke", "--id", &registry, "--source-account", &l0, "--", "register", "--kind", &kind,
                                 "--key_data", key_data, "--attrs", &attrs, "--pop", pop, EMPTY_PQZ_POP]);
        assert_eq!(out.trim_matches('"'), hx(&k.id()), "register({}) returned another id", k.row);
        let cost = log_cost(&format!("register {} (lane 0 via CLI)", k.row), &tx).await;
        registered.push(Registered { key: k, id: k.id(), tx, cost });
    }
    Stack { registry, token, token_b, router, executor, mandate, dex, registered }
}

/// The node under test: the adapter over lanes 0 and 1 (router, DEX and both tokens configured) and a fake Odoo whose
/// index cursor starts at the current ledger.
struct Node {
    state: Arc<Mutex<FakeOdoo>>,
    odoo: Odoo,
    adapter: SorobanAdapter,
}

impl Node {
    async fn new(st: &Stack) -> Node {
        let start = latest_ledger().await;
        let state = Arc::new(Mutex::new(FakeOdoo {
            tokens: vec![st.token.clone(), st.token_b.clone()],
            others: vec![st.router.clone()],
            indexed_block: start - 1,
            ..Default::default()
        }));
        let odoo = odoo_at(start_fake(state.clone()).await);
        let mut cfg = chain_cfg(false);
        cfg.tokens = [&st.token, &st.token_b].iter().map(|t| TokenCfg { address: t.to_string(), decimals: 7 }).collect();
        let mut rf = toml::Table::new();
        rf.insert("router".into(), st.router.clone().into());
        rf.insert("min_amount".into(), 1.into());
        cfg.params.insert("relay_fee".into(), rf.into());
        cfg.params.insert("dex".into(), st.dex.clone().into());
        let adapter = SorobanAdapter::new(&cfg, &[key(0), key(1)]).unwrap();
        assert_eq!(adapter.lanes()[0].address, g(&key(0)));
        Node { state, odoo, adapter }
    }

    /// One `lane_step` on `lane` with `job` queued: its final state and its last report.
    async fn run(&self, lane: usize, job: Value) -> (String, Value) {
        let id = job["id"].as_i64().unwrap();
        self.state.lock().unwrap().jobs.push(job);
        assert!(lane_step(&self.adapter, &self.odoo, lane, &format!("e2e#{lane}")).await.unwrap());
        let o = self.state.lock().unwrap();
        assert!(o.refused.is_empty(), "{:?}", o.refused);
        (last_state(&o, id), o.reports.iter().rev().find(|r| r["job_id"] == id).cloned().unwrap_or_default())
    }

    /// `run`, expecting `mined`; logs the cost and returns the transaction hash.
    async fn mined(&self, what: &str, lane: usize, job: Value) -> String {
        let id = job["id"].as_i64().unwrap();
        let (state, last) = self.run(lane, job).await;
        assert_eq!(state, "mined", "{what}: {last}");
        let tx = report_of(&self.state.lock().unwrap(), id, "signed")["tx_hash"].as_str().unwrap().to_string();
        log_cost(&format!("{what} (ua_metatx job, lane {lane})"), &tx).await;
        tx
    }

    /// `index_step` up to the current head (finality: instant); the rows Odoo ingested.
    async fn index(&self) -> Vec<Value> {
        let head = latest_ledger().await;
        for _ in 0..60 {
            let _ = index_step(&self.adapter, &self.odoo).await.unwrap();
            if self.state.lock().unwrap().indexed_block >= head {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        let o = self.state.lock().unwrap();
        assert!(o.indexed_block >= head, "indexed {} < head {head}", o.indexed_block);
        o.ingested.clone()
    }
}

fn row<'a>(rows: &'a [Value], event: &str, tx: &str) -> &'a Value {
    rows.iter().find(|e| e["event"] == event && e["tx_hash"] == tx).unwrap_or_else(|| panic!("no {event} row of {tx}: {rows:?}"))
}

fn ua0x(u: &[u8; 32]) -> String {
    format!("0x{}", hx(u))
}

#[tokio::test]
#[ignore]
async fn e2e_soroban_ua_register_passkey_and_mldsa65() {
    let st = stack().await;
    let attrs = format!("{{\"kem_pk\":\"\",\"kem_version\":0,\"pqz_key\":\"\",\"pqz_pop_hash\":\"{}\"}}", "0".repeat(64));
    for r in &st.registered {
        println!(
            "T10 register {}: ua {} tx {} ledger {} cpu_insns {} resource_fee {} fee_charged {} stroops",
            r.key.row, ua0x(&r.id), r.tx, r.cost.ledger, r.cost.instructions, r.cost.resource_fee, r.cost.fee_charged
        );
        let reg = r.key.registration();
        let (kind, key_data) = (reg["kind"].to_string(), reg["keyData"].as_str().unwrap().trim_start_matches("0x").to_string());
        assert_eq!(view(&st.registry, "ua_of", &["--kind", &kind, "--key_data", &key_data]), hx(&r.id));
        assert_eq!(view(&st.registry, "receivable", &["--ua", &hx(&r.id)]), "true", "{} can spend here (S9)", r.key.row);
        let record: Value = serde_json::from_str(&view(&st.registry, "record_of", &["--ua", &hx(&r.id)])).unwrap();
        assert_eq!(record["kind"].to_string(), kind);
        assert_eq!(record["signable"], json!(true), "{record}");
        assert!(view_i128(&st.registry, "ua_count", &["--kind", &kind]) >= 1);
        // CTR-UA-07: an identical registration by another submitter is refused (AlreadyRegistered = 4), never a second record
        let (l1, pop) = (secret(1), reg["pop"].as_str().unwrap().trim_start_matches("0x").to_string());
        let (ok, _, err) = cli_raw(&["contract", "invoke", "--id", &st.registry, "--source-account", &l1, "--", "register", "--kind", &kind,
                                     "--key_data", &key_data, "--attrs", &attrs, "--pop", &pop, EMPTY_PQZ_POP]);
        assert!(!ok && err.contains("#4"), "a second register of {} must be AlreadyRegistered: {err}", r.key.row);
    }
    assert_eq!(view(&st.registry, "relayers", &[]).replace([' ', '\n'], ""), format!("[\"{}\",\"{}\"]", g(&key(0)), g(&key(1))));
}

#[tokio::test]
#[ignore]
async fn e2e_soroban_ua_transfer_to_ua_and_ua_pay_relayed() {
    let st = stack().await;
    let node = Node::new(st).await;
    let (pk, ml) = (PASSKEY.id(), MLDSA65.id());
    let admin = g(&key(DEPLOYER));
    send("mint (native)", DEPLOYER, &st.token, "mint", &["--to", &admin, "--amount", "1000000"]).await;
    let before = view_i128(&st.token, "ua_balance", &["--ua", &hx(&pk)]);
    // CTR-UA-28: a native holder pays into the UA ledger
    send("transfer_to_ua (native -> passkey UA)", DEPLOYER, &st.token, "transfer_to_ua", &["--from", &admin, "--to", &hx(&pk), "--amount", "100000"]).await;
    assert_eq!(view_i128(&st.token, "ua_balance", &["--ua", &hx(&pk)]), before + 100_000);

    // ua_pay passkey -> mldsa65, bound to lane 0 (S8), relayed by the node
    let (pay_ref, vu, lane0) = (fresh(), now() + 600, g(&key(0)));
    let ml_before = view_i128(&st.token, "ua_balance", &["--ua", &hx(&ml)]);
    let mut args = vec![bytes(&pk), h_ua(&ml), i128v(1_000), bytes(&pay_ref), ScVal::U64(vu), addr(&lane0)];
    let d = digest(&st.token, "ua_pay", &args);
    args.push(PASSKEY.sign(&d, "metatx"));
    let tx = node.mined("ua_pay passkey -> mldsa65", 0, ua_job(201, &st.token, "ua_pay", args, vec![])).await;
    assert_eq!(view_i128(&st.token, "ua_balance", &["--ua", &hx(&ml)]), ml_before + 1_000);
    assert_eq!(view(&st.token, "ua_ref_used", &["--ua", &hx(&pk), "--pay_ref", &hx(&pay_ref)]), "true");

    // finality + the rows: the UA payment as a PaymentSettled, the UA-signed entry as a MetaTransactionExecuted
    let rows = node.index().await;
    let paid = row(&rows, "PaymentSettled", &tx);
    assert_eq!((paid["from"].as_str(), paid["to"].as_str()), (Some(ua0x(&pk).as_str()), Some(ua0x(&ml).as_str())), "{paid}");
    assert_eq!(paid["amount"], "1000");
    assert_eq!(paid["entry_ref"], ua0x(&pay_ref));
    assert_eq!(paid["contract"], json!(st.token));
    assert_eq!(row(&rows, "MetaTransactionExecuted", &tx)["digest"], ua0x(&d));
    assert!(rows.iter().any(|e| e["event"] == "Transfer" && e["from"] == json!(admin) && e["to"] == json!(ua0x(&pk)) && e["amount"] == "100000"),
            "transfer_to_ua row: {rows:?}");
    println!("T10 ua_pay rows: {}", serde_json::to_string(paid).unwrap());
}

#[tokio::test]
#[ignore]
async fn e2e_soroban_ua_relay_fee() {
    let st = stack().await;
    let node = Node::new(st).await;
    let (pk, lane0, lane1) = (PASSKEY.id(), g(&key(0)), g(&key(1)));
    send("mint_to_ua (passkey)", DEPLOYER, &st.token, "mint_to_ua", &["--to", &hx(&pk), "--amount", "10000"]).await;
    // ua_relay, open mode (to = the router, forwarded to the submitting lane): target token.balance(lane 1)
    let (salt, vu, fee) = (fresh(), now() + 600, 250i128);
    let target_args = vec![addr(&lane1)];
    let rf = relay_ref(&network(), &sc(&st.token), &sym("balance"), &target_args, &salt);
    let inner = [bytes(&pk), h_addr(&st.router), i128v(fee), bytes(&rf), ScVal::U64(vu), addr(&st.router)];
    let d = digest(&st.token, "ua_pay", &inner);
    let args = vec![bytes(&pk), addr(&st.token), ScVal::Symbol(sym("balance")), vecv(target_args), bytes(&salt), addr(&st.token),
                    h_addr(&st.router), i128v(fee), ScVal::U64(vu), addr(&lane0), PASSKEY.sign(&d, "metatx")];
    let lane_before = view_i128(&st.token, "balance", &["--id", &lane0]);
    let tx = node.mined("ua_relay passkey fee, open mode", 0, ua_job(301, &st.router, "ua_relay", args, vec![])).await;
    assert_eq!(view_i128(&st.token, "balance", &["--id", &lane0]), lane_before + fee, "the fee reached the submitting lane");
    assert_eq!(view_i128(&st.token, "balance", &["--id", &st.router]), 0, "nothing rests on the router");
    assert_eq!(view_i128(&st.token, "balance", &["--id", &st.executor]), 0, "nothing rests on the executor");
    assert_eq!(view(&st.token, "ua_ref_used", &["--ua", &hx(&pk), "--pay_ref", &hx(&rf)]), "true");

    // the router's RelayFeePaid is joined to the fee's PaymentSettled (`indexer::join_pay_events`), never sent alone
    let rows = node.index().await;
    assert!(!rows.iter().any(|e| e["event"] == "RelayFeePaid"), "{rows:?}");
    let r = row(&rows, "PaymentSettled", &tx);
    assert_eq!((r["from"].as_str(), r["to"].as_str()), (Some(ua0x(&pk).as_str()), Some(st.router.as_str())), "{r}");
    assert_eq!(r["entry_ref"], ua0x(&rf));
    assert_eq!(r["amount"], fee.to_string());
    assert_eq!(r["contract"], json!(st.token));
    assert_eq!(r["relay_payee"], json!(lane0), "open mode: the submitting lane is paid");
    assert_eq!(r["relay_target"], json!(st.token));
    println!("T10 ua_relay fee row (PaymentSettled + RelayFeePaid): {}", serde_json::to_string(r).unwrap());
}

#[tokio::test]
#[ignore]
async fn e2e_soroban_ua_mandate_pays_ua_payee() {
    let st = stack().await;
    let node = Node::new(st).await;
    let (pk, ml) = (PASSKEY.id(), MLDSA65.id());
    let (vu, zero) = (now() + 600, "0".repeat(64));
    let (vus, exp) = (vu.to_string(), (now() + 86_400).to_string());
    // the native owner sets the passkey UA as delegate and the mldsa65 UA as payee (host auth: auth empty)
    send("mtx_set_mandate (native owner, delegate = passkey UA)", DEPLOYER, &st.mandate, "mtx_set_mandate", &[
        "--token", &st.token, "--delegate", &ua_json(&pk), "--max_per_payment", "50000", "--max_per_period", "200000",
        "--period_seconds", "86400", "--expiry", &exp, "--lane", &zero, "--nonce", "0", "--valid_until", &vus, EMPTY_AUTH]).await;
    send("mtx_set_payee (native owner, payee = mldsa65 UA)", DEPLOYER, &st.mandate, "mtx_set_payee", &[
        "--token", &st.token, "--payee", &ua_json(&ml), "--allowed", "true", "--lane", &zero, "--nonce", "1", "--valid_until", &vus,
        EMPTY_AUTH]).await;
    send("mint (to the mandate)", DEPLOYER, &st.token, "mint", &["--to", &st.mandate, "--amount", "100000"]).await;
    let epoch: u64 = view(&st.mandate, "epoch", &["--token", &st.token]).parse().unwrap();

    // the UA delegate pays the UA payee; relayer None, lane 1 submits
    let (pay_ref, before) = (fresh(), view_i128(&st.token, "ua_balance", &["--ua", &hx(&ml)]));
    let mut args = vec![addr(&st.token), h_ua(&ml), i128v(5_000), bytes(&pay_ref), ScVal::U64(epoch), ScVal::U64(vu), ScVal::Void];
    let d = digest(&st.mandate, "mtx_mandate_pay", &args);
    args.push(PASSKEY.sign(&d, "metatx"));
    let tx = node.mined("mtx_mandate_pay passkey delegate -> mldsa65 payee", 1, ua_job(401, &st.mandate, "mtx_mandate_pay", args, vec![])).await;
    assert_eq!(view_i128(&st.token, "ua_balance", &["--ua", &hx(&ml)]), before + 5_000);
    assert_eq!(view(&st.mandate, "paid", &["--pay_ref", &hx(&pay_ref)]), "true");

    let rows = node.index().await;
    let paid = row(&rows, "PaymentSettled", &tx);
    assert_eq!((paid["from"].as_str(), paid["to"].as_str()), (Some(st.mandate.as_str()), Some(ua0x(&ml).as_str())), "{paid}");
    assert_eq!(paid["entry_ref"], ua0x(&pay_ref));
    assert_eq!(paid["amount"], "5000");
    println!("T10 mandate PaymentSettled row: {}", serde_json::to_string(paid).unwrap());
}

#[tokio::test]
#[ignore]
async fn e2e_soroban_ua_dex_leg() {
    let st = stack().await;
    let node = Node::new(st).await;
    let (ml, taker, lane0) = (MLDSA65.id(), key(TAKER), g(&key(0)));
    let tg = g(&taker);
    send("set_market (fees off)", DEPLOYER, &st.dex, "set_market", &["--token_a", &st.token, "--token_b", &st.token_b, "--market",
         "{\"fee_on\":false,\"maker_fee_ppm\":0,\"taker_fee_ppm\":0}"]).await;
    send("mint_to_ua (mldsa65, token A)", DEPLOYER, &st.token, "mint_to_ua", &["--to", &hx(&ml), "--amount", "10000"]).await;
    send("mint (taker, token B)", DEPLOYER, &st.token_b, "mint", &["--to", &tg, "--amount", "20000"]).await;
    let ledger = latest_ledger().await;
    send("approve (taker -> DEX, token B)", TAKER, &st.token_b, "approve", &["--from", &tg, "--spender", &st.dex, "--amount", "20000",
         "--expiration_ledger", &(ledger + 5_000).to_string()]).await;

    // maker: the mldsa65 UA sells 1,000 A for 2,000 B into its UA balance; taker: native, the opposite
    let expiry = now() + 600;
    let salt = u64::from_be_bytes(fresh()[..8].try_into().unwrap());
    let maker = order(h_ua(&ml), h_ua(&ml), &lane0, &st.token, 1_000, &st.token_b, 2_000, expiry, salt);
    let tko = order(h_addr(&tg), h_addr(&tg), &lane0, &st.token_b, 2_000, &st.token, 1_000, expiry, salt);
    let maker_auth = MLDSA65.sign(&digest(&st.token, "ua_order", &[addr(&st.dex), maker.clone()]), "trade");
    // the native taker's host auth: require_auth_for_args((order,)) rooted at settle
    let pre = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: Hash(network()),
        nonce: i64::from_be_bytes(fresh()[..8].try_into().unwrap()),
        signature_expiration_ledger: ledger as u32 + 1_000,
        invocation: SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: sc(&st.dex),
                function_name: sym("settle"),
                args: vec![tko.clone()].try_into().unwrap(),
            }),
            sub_invocations: Default::default(),
        },
    })
    .to_xdr(Limits::none())
    .unwrap();
    let sig = taker.sign(&Sha256::digest(&pre)).unwrap();
    let auth = vec![json!({"payload": hx(&pre), "from": tg, "signature": hx(&sig)})];

    let bal = |t: &str, f: &str, a: &str, v: &str| view_i128(t, f, &[a, v]);
    let (ml_a, ml_b) = (bal(&st.token, "ua_balance", "--ua", &hx(&ml)), bal(&st.token_b, "ua_balance", "--ua", &hx(&ml)));
    let (tk_a, tk_b) = (bal(&st.token, "balance", "--id", &tg), bal(&st.token_b, "balance", "--id", &tg));
    let args = vec![maker, tko, i128v(1_000), maker_auth, bytes(&[])];
    node.mined("settle UA maker (mldsa65) vs native taker", 0, ua_job(501, &st.dex, "settle", args, auth)).await;
    assert_eq!(bal(&st.token, "ua_balance", "--ua", &hx(&ml)), ml_a - 1_000);
    assert_eq!(bal(&st.token_b, "ua_balance", "--ua", &hx(&ml)), ml_b + 2_000);
    assert_eq!(bal(&st.token, "balance", "--id", &tg), tk_a + 1_000);
    assert_eq!(bal(&st.token_b, "balance", "--id", &tg), tk_b - 2_000);
    assert_eq!(bal(&st.token, "balance", "--id", &st.dex), 0, "the DEX holds nothing after the settle");
    assert_eq!(bal(&st.token_b, "balance", "--id", &st.dex), 0);
}

/// S14 / spec §8 end to end: a validly signed `ua_relay` whose target would spend lane 0's own authority
/// (`token.approve(lane 0, …)`) dies at SIMULATION with the host's `Error(Auth, …)`: the job carries the node's
/// `SourceAccount` entry rooted at exactly the call, so the RPC simulates in enforcing mode and the host refuses the
/// nested `lane.require_auth()` before the node's recorded-auth guard (`check_recorded_auth`) is reached. Nothing is
/// signed or sent: the lane's sequence, its allowance and the UA's fee ref are unchanged. The node guard itself is
/// covered by the T9 unit tests (`ua_metatx_refuses_extra_source_account_auth`), not here.
#[tokio::test]
#[ignore]
async fn e2e_soroban_ua_lane_authority_not_lent() {
    let st = stack().await;
    let node = Node::new(st).await;
    let (pk, lane0, by) = (PASSKEY.id(), g(&key(0)), g(&key(BYSTANDER)));
    send("mint_to_ua (passkey)", DEPLOYER, &st.token, "mint_to_ua", &["--to", &hx(&pk), "--amount", "10000"]).await;
    // a validly signed ua_relay whose target needs lane 0's own authority: token.approve(lane 0, bystander, …)
    let ledger = latest_ledger().await;
    let (salt, vu, fee) = (fresh(), now() + 600, 250i128);
    let target_args = vec![addr(&lane0), addr(&by), i128v(1_000_000), ScVal::U32(ledger as u32 + 1_000)];
    let rf = relay_ref(&network(), &sc(&st.token), &sym("approve"), &target_args, &salt);
    let inner = [bytes(&pk), h_addr(&st.router), i128v(fee), bytes(&rf), ScVal::U64(vu), addr(&st.router)];
    let d = digest(&st.token, "ua_pay", &inner);
    let args = vec![bytes(&pk), addr(&st.token), ScVal::Symbol(sym("approve")), vecv(target_args), bytes(&salt), addr(&st.token),
                    h_addr(&st.router), i128v(fee), ScVal::U64(vu), addr(&lane0), PASSKEY.sign(&d, "metatx")];
    let seq = node.adapter.sequence(0).await.unwrap();
    let (state, last) = node.run(0, ua_job(601, &st.router, "ua_relay", args, vec![])).await;
    println!("T10 lane authority not lent (host refusal at simulation): job state {state}, reason {}", last["error"]);
    assert_eq!(state, "dead", "refused before submission: {last}");
    let reason = last["error"].as_str().unwrap_or_default();
    assert!(reason.starts_with("simulation:") && reason.contains("Error(Auth,"), "the host's auth refusal at simulation: {reason}");
    assert!(report_of(&node.state.lock().unwrap(), 601, "signed").is_null(), "never signed");
    assert_eq!(node.adapter.sequence(0).await.unwrap(), seq, "the lane's sequence is unchanged");
    assert_eq!(view_i128(&st.token, "allowance", &["--from", &lane0, "--spender", &by]), 0, "no allowance from the lane");
    assert_eq!(view(&st.token, "ua_ref_used", &["--ua", &hx(&pk), "--pay_ref", &hx(&rf)]), "false", "the UA's fee is unspent");
}
