//! UA-Soroban local e2e (spec §10, S17; plan T10): `smartcontracts/soroban/scripts/e2e-local.sh`, or by hand with a
//! running quickstart: `cargo test --test e2e_soroban_ua -- --ignored --test-threads=1 --nocapture` (env: see
//! `soroban_common`; T14 runs it against the Stellar testnet).
//!
//! One stack per run, deployed through `smartcontracts/scripts/deploy.sh soroban` (`relay_fee` = the executor and the
//! router): the registry (relayers = the two lanes), two tokens bound to it, the relay-fee router, a mandate owned by a
//! native account and the DEX. A passkey (`webauthn-p256`) UA and an `mldsa65` UA are registered by lane 0 through the
//! CLI (anyone may submit; the node's `call` job is Part B's). UA signatures come from
//! `clients/clientkeys/scripts/soroban-sign.mjs` (SOR-D13); UA entries go through the node as `ua_metatx` jobs
//! (`lane_step`), and their rows through `index_step`; a native payer's relay fee and a settle of two native makers go the same way.
//! Every transaction logs its CPU instructions and fees.
mod soroban_common;

use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use scaas_node::adapter::{index_step, lane_step, ChainAdapter};
use scaas_node::adapters::soroban::{holder_addr, op_digest, relay_ref, SorobanAdapter};
use scaas_node::config::TokenCfg;
use scaas_node::odoo::Odoo;
use scaas_node::signer::Signer as _;
use serde_json::{json, Value};
use scaas_ua::ua8::{check_membership, MemberSig};
use sha2::{Digest, Sha256};
use soroban_common::*;
use stellar_xdr::{
    Int128Parts, InvokeContractArgs, ScAddress, ScMap, ScMapEntry, ScSymbol, ScVal, ScVec, SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
};
use tokio::sync::OnceCell;

const OPS: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../smartcontracts/soroban/vectors/ua-ops.json"));
const PORTABLE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../smartcontracts/vectors/ua/portable.json"));
const SIGNER: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../clients/clientkeys/scripts/soroban-sign.mjs");
/// Account indexes of the test mnemonic (`soroban_common::key`): lanes 0 and 1, the deployer (admin, mandate owner,
/// native payer), the DEX's native taker, and a bystander.
const DEPLOYER: u32 = 7;
const TAKER: u32 = 9;
const BYSTANDER: u32 = 8;
/// Empty `Bytes` for the CLI: the JSON string `""` (a bare empty value is refused as missing).
const EMPTY_PQZ_POP: &str = "--pqz_pop=\"\"";
const EMPTY_AUTH: &str = r#"--auth={"key_data":"","members":[],"signature":""}"#;

/// A UA test signer: the `soroban-sign.mjs` kind and key index, and its `ua-ops.json` registration row.
#[derive(Clone, Copy)]
struct UaKey {
    kind: &'static str,
    index: u32,
    row: &'static str,
}
const PASSKEY: UaKey = UaKey { kind: "webauthn-p256", index: 0, row: "webauthn-p256" };
const MLDSA65: UaKey = UaKey { kind: "mldsa65", index: 2, row: "mldsa65#2" };
const MSIG: UaKey = UaKey { kind: "msig", index: 0, row: "msig-2of3" };

impl UaKey {
    fn registration(&self) -> Value {
        let ops: Value = serde_json::from_str(OPS).unwrap();
        ops["registrations"].as_array().unwrap().iter().find(|r| r["name"] == self.row).cloned().unwrap()
    }
    fn id(&self) -> [u8; 32] {
        unhex(self.registration()["ua"].as_str().unwrap()).try_into().unwrap()
    }
    /// `auth` for (`digest`, `purpose`) by the clientkeys e2e signer, as a job names it.
    fn sign(&self, digest: &[u8; 32], purpose: &str) -> Value {
        let out = Command::new("node").args([SIGNER, self.kind, &self.index.to_string(), &hx(digest), purpose]).output().expect("node");
        assert!(out.status.success(), "soroban-sign.mjs: {}", String::from_utf8_lossy(&out.stderr));
        let v: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(v["ua"].as_str().unwrap(), format!("0x{}", hx(&self.id())), "{} signs as another UA", self.row);
        v["sig"].clone()
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

/// The empty `UaSig` of a native leg (host auth).
fn no_auth() -> Value {
    json!({"key_data": "0x", "signature": "0x", "members": []})
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

fn invocation(contract: &str, f: &str, args: Vec<ScVal>, subs: Vec<SorobanAuthorizedInvocation>) -> SorobanAuthorizedInvocation {
    let call = InvokeContractArgs { contract_address: sc(contract), function_name: sym(f), args: args.try_into().unwrap() };
    SorobanAuthorizedInvocation { function: SorobanAuthorizedFunction::ContractFn(call), sub_invocations: subs.try_into().unwrap() }
}

/// What a native maker signs: `require_auth_for_args((order,))` rooted at `settle`.
fn settle_root(dex: &str, order: &ScVal) -> SorobanAuthorizedInvocation {
    invocation(dex, "settle", vec![order.clone()], vec![])
}

/// The op digest a UA signs (NET-SOR-16): the entry's arguments without `auth`.
fn digest(contract: &str, f: &str, args: &[ScVal]) -> [u8; 32] {
    op_digest(&network(), &sc(contract), &sym(f), args).unwrap()
}

/// A DEX `Order` as a job names it, the same order as `order`'s; `salt` as a decimal string (past 2^53).
#[allow(clippy::too_many_arguments)]
fn order_json(maker: &Value, relayer: &str, sell: &str, sell_amount: i128, buy: &str, buy_amount: i128, expiry: u64, salt: u64) -> Value {
    json!({"maker": maker, "destination": maker, "relayer": relayer, "sell_token": sell, "sell_amount": sell_amount.to_string(),
           "buy_token": buy, "buy_amount": buy_amount.to_string(), "max_fee_ppm": 0, "expiry": expiry, "salt": salt.to_string()})
}

/// SOR-D14's job, named: `{kind: "ua_metatx", op: {contract, function, args: {…every argument, auth included}, auth?}}`.
/// The digest each test signs comes from `ScVal`s of its own, so a field the node builds differently fails on chain.
fn ua_job(id: i64, contract: &str, function: &str, args: Value, auth: Vec<Value>) -> Value {
    let mut op = json!({"contract": contract, "function": function, "args": args});
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

    let z = "0".repeat(64);
    let attrs = format!("{{\"kem\":{{\"mlkem_ek\":\"\",\"scheme\":0,\"x25519\":\"{z}\"}},\"kem_pk_hash\":\"{z}\",\"pqz_key\":\"\",\"pqz_pop_hash\":\"{z}\"}}");
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
        cfg.params.insert("ua_registry".into(), st.registry.clone().into());
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

/// A registry write as the node's `call` job.
fn call_job(id: i64, st: &Stack, f: &str, args: Value) -> Value {
    json!({"id": id, "kind": "call", "op": {"contract": st.registry, "function": f, "args": args, "valid_until": now() + 600}})
}

/// `row` of `ua-ops.json` or `portable.json` through the node, once a stack: `register`, or `register_msig` of an `msig` with an empty `pop`.
async fn ensure_registered(node: &Node, st: &Stack, id: i64, r: &Value, relayer: Value) {
    let ua = r["ua"].as_str().unwrap();
    if view(&st.registry, "record_of", &["--ua", ua.trim_start_matches("0x")]) != "null" {
        return;
    }
    let z = format!("0x{}", "00".repeat(32));
    let attrs = json!({"pqz_key": "0x", "pqz_pop_hash": z, "kem": {"scheme": 0, "mlkem_ek": "0x", "x25519": z}, "kem_pk_hash": z});
    let job = if r["kind"] == 0x0120 {
        let members: Vec<Value> = r["members"].as_array().unwrap().iter().map(|m| json!({"kind": m["kind"], "id": m["id"], "weight": m["weight"]})).collect();
        call_job(id, st, "register_msig", json!({"structure": {"threshold": r["threshold"], "members": members}, "attrs": attrs, "pop": [], "pqz_pop": "0x", "relayer": relayer}))
    } else {
        call_job(id, st, "register", json!({"kind": r["kind"], "key_data": r["keyData"], "attrs": attrs, "pop": r["pop"], "pqz_pop": "0x", "relayer": relayer}))
    };
    node.mined(&format!("register {}", r["name"]), 0, job).await;
}

/// CTR-UA-37: `accept_membership` as the node's job, `valid_until` named by the job: nothing signed names one.
fn accept_job(id: i64, st: &Stack, ua: &str, index: &Value, sig: &str, relayer: Value, auth: Vec<Value>) -> Value {
    let args = json!({"ua": ua, "member_sig": {"index": index, "key_data": "0x", "sig": sig}, "relayer": relayer});
    let mut job = ua_job(id, &st.registry, "accept_membership", args, auth);
    job["op"]["valid_until"] = json!(now() + 600);
    job
}

/// A `registrations[]` row of `portable.json` by its id.
fn row_of<'a>(p: &'a Value, ua: &str) -> Option<&'a Value> {
    p["registrations"].as_array().unwrap().iter().find(|r| r["ua"] == ua)
}

fn member_accepted(st: &Stack, ua: &str, index: u64) -> bool {
    view(&st.registry, "member_accepted", &["--ua", ua.trim_start_matches("0x"), "--index", &index.to_string()]) == "true"
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
    let z = "0".repeat(64);
    let attrs = format!("{{\"kem\":{{\"mlkem_ek\":\"\",\"scheme\":0,\"x25519\":\"{z}\"}},\"kem_pk_hash\":\"{z}\",\"pqz_key\":\"\",\"pqz_pop_hash\":\"{z}\"}}");
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
    let d = digest(&st.token, "ua_pay", &[bytes(&pk), h_ua(&ml), i128v(1_000), bytes(&pay_ref), ScVal::U64(vu), addr(&lane0)]);
    let args = json!({"from": ua0x(&pk), "to": {"Ua": ua0x(&ml)}, "amount": "1000", "pay_ref": ua0x(&pay_ref), "valid_until": vu, "relayer": lane0,
                      "auth": PASSKEY.sign(&d, "metatx")});
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
    let args = json!({"payer": ua0x(&pk), "target": st.token, "func": "balance", "args": [{"type": "Address", "value": lane1}], "salt": ua0x(&salt), "token": st.token,
                      "to": {"Addr": st.router}, "amount": fee.to_string(), "valid_until": vu, "relayer": lane0, "auth": PASSKEY.sign(&d, "metatx")});
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
    let d = digest(&st.mandate, "mtx_mandate_pay", &[addr(&st.token), h_ua(&ml), i128v(5_000), bytes(&pay_ref), ScVal::U64(epoch), ScVal::U64(vu), ScVal::Void]);
    let args = json!({"token": st.token, "payee": {"Ua": ua0x(&ml)}, "amount": "5000", "pay_ref": ua0x(&pay_ref), "epoch": epoch, "valid_until": vu, "relayer": null,
                      "auth": PASSKEY.sign(&d, "metatx")});
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
    let nonce = i64::from_be_bytes(fresh()[..8].try_into().unwrap());
    let (payload, sig) = signed_auth(&taker, nonce, ledger as u32 + 1_000, &settle_root(&st.dex, &tko));
    let auth = vec![json!({"payload": payload, "from": tg, "signature": sig})];

    let bal = |t: &str, f: &str, a: &str, v: &str| view_i128(t, f, &[a, v]);
    let (ml_a, ml_b) = (bal(&st.token, "ua_balance", "--ua", &hx(&ml)), bal(&st.token_b, "ua_balance", "--ua", &hx(&ml)));
    let (tk_a, tk_b) = (bal(&st.token, "balance", "--id", &tg), bal(&st.token_b, "balance", "--id", &tg));
    let (ml_h, tk_h) = (json!({"Ua": ua0x(&ml)}), json!({"Addr": tg}));
    let args = json!({"maker": order_json(&ml_h, &lane0, &st.token, 1_000, &st.token_b, 2_000, expiry, salt),
                      "taker": order_json(&tk_h, &lane0, &st.token_b, 2_000, &st.token, 1_000, expiry, salt),
                      "maker_fill": "1000", "maker_auth": maker_auth, "taker_auth": no_auth()});
    node.mined("settle UA maker (mldsa65) vs native taker", 0, ua_job(501, &st.dex, "settle", args, auth)).await;
    assert_eq!(bal(&st.token, "ua_balance", "--ua", &hx(&ml)), ml_a - 1_000);
    assert_eq!(bal(&st.token_b, "ua_balance", "--ua", &hx(&ml)), ml_b + 2_000);
    assert_eq!(bal(&st.token, "balance", "--id", &tg), tk_a + 1_000);
    assert_eq!(bal(&st.token_b, "balance", "--id", &tg), tk_b - 2_000);
    assert_eq!(bal(&st.token, "balance", "--id", &st.dex), 0, "the DEX holds nothing after the settle");
    assert_eq!(bal(&st.token_b, "balance", "--id", &st.dex), 0);
}

/// A native payer's relay fee through the node: the payer's root is `relay`'s eight `require_auth_for_args` arguments with
/// `token.pay` under it, and the transaction carries that `Address` entry and the lane's `SourceAccount` entry together. The node
/// builds the call from the named root; the host checks the signature over what it rebuilt.
#[tokio::test]
#[ignore]
async fn e2e_soroban_native_relay_fee() {
    let st = stack().await;
    let node = Node::new(st).await;
    let (payer, lane0, lane1) = (key(TAKER), g(&key(0)), g(&key(1)));
    let pg = g(&payer);
    send("mint (native payer)", DEPLOYER, &st.token, "mint", &["--to", &pg, "--amount", "10000"]).await;
    let (salt, vu, fee) = (fresh(), now() + 600, 250i128);
    let target_args = vec![addr(&lane1)];
    let rf = relay_ref(&network(), &sc(&st.token), &sym("balance"), &target_args, &salt);
    let pay = invocation(&st.token, "pay", vec![addr(&pg), addr(&st.router), i128v(fee), bytes(&rf), ScVal::U64(vu)], vec![]);
    let root = invocation(&st.router, "relay", vec![addr(&st.token), ScVal::Symbol(sym("balance")), vecv(target_args), bytes(&salt), addr(&st.token), addr(&st.router),
                                                    i128v(fee), ScVal::U64(vu)], vec![pay]);
    let (nonce, expiry) = (i64::from_be_bytes(fresh()[..8].try_into().unwrap()), latest_ledger().await as u32 + 1_000);
    let (payload, signature) = signed_auth(&payer, nonce, expiry, &root);
    let job = |id: i64, signature: &str| json!({"id": id, "kind": "signed_op", "op": {"kind": "relay_fee", "payload": payload, "from": pg, "signature": signature,
                                                "contract": st.router, "valid_until": vu, "ref": ua0x(&rf), "extra": {}}});

    // one change from the passing job: a signature over other bytes. Dead at simulation, nothing sent
    let seq = node.adapter.sequence(0).await.unwrap();
    let other = signed_auth(&payer, nonce.wrapping_add(1), expiry, &root).1;
    let (state, last) = node.run(0, job(700, &other)).await;
    println!("native relay, a signature over other bytes: job state {state}, reason {}", last["error"]);
    assert_eq!(state, "dead", "{last}");
    let reason = last["error"].as_str().unwrap();
    assert!(reason.starts_with("simulation:") && reason.contains("Error(Auth,"), "the host's auth refusal at simulation: {reason}");
    assert!(report_of(&node.state.lock().unwrap(), 700, "signed").is_null(), "never signed");
    assert_eq!(node.adapter.sequence(0).await.unwrap(), seq, "the lane's sequence is unchanged");

    let (lane_before, payer_before) = (view_i128(&st.token, "balance", &["--id", &lane0]), view_i128(&st.token, "balance", &["--id", &pg]));
    let tx = node.mined("relay native fee, open mode", 0, job(701, &signature)).await;
    assert_eq!(view_i128(&st.token, "balance", &["--id", &lane0]), lane_before + fee, "the fee reached the submitting lane");
    assert_eq!(view_i128(&st.token, "balance", &["--id", &pg]), payer_before - fee);
    assert_eq!(view_i128(&st.token, "balance", &["--id", &st.router]), 0, "nothing rests on the router");
    assert_eq!(view_i128(&st.token, "balance", &["--id", &st.executor]), 0, "nothing rests on the executor");

    let rows = node.index().await;
    let r = row(&rows, "PaymentSettled", &tx);
    assert_eq!((r["from"].as_str(), r["to"].as_str()), (Some(pg.as_str()), Some(st.router.as_str())), "{r}");
    assert_eq!(r["entry_ref"], ua0x(&rf));
    assert_eq!(r["relay_payee"], json!(lane0), "open mode: the submitting lane is paid");
    println!("native relay fee row: {}", serde_json::to_string(r).unwrap());
}

/// CTR-UA-37 on a real host, through the node. A listed `msig` holds funds and spends none: a good signature of an unaccepted slot is
/// refused at simulation, nothing sent, with no slot accepted and with one of the two needed; a member's bad acceptance is refused too;
/// the same payment runs after the second slot accepts. A repeat is refused unsent: on chain a no-op, on the lane's fee.
#[tokio::test]
#[ignore]
async fn e2e_soroban_ua_member_accepts_then_counts() {
    let st = stack().await;
    let node = Node::new(st).await;
    let ops: Value = serde_json::from_str(OPS).unwrap();
    let rows = ops["registrations"].as_array().unwrap();
    let by_name = |n: &str| rows.iter().find(|r| r["name"] == n).unwrap().clone();
    for (i, n) in ["ed25519", "p256", "mldsa65#1", "msig-2of3"].iter().enumerate() {
        ensure_registered(&node, st, 900 + i as i64, &by_name(n), Value::Null).await;
    }
    let (ms, id) = (MSIG.registration(), MSIG.id());
    let ua = ua0x(&id);
    assert_eq!(view(&st.registry, "receivable", &["--ua", &hx(&id)]), "true", "listed: it may hold");
    send("mint_to_ua (msig)", DEPLOYER, &st.token, "mint_to_ua", &["--to", &hx(&id), "--amount", "5000"]).await;
    let to = PASSKEY.id();
    let (pay_ref, vu, lane0) = (fresh(), now() + 600, g(&key(0)));
    let d = digest(&st.token, "ua_pay", &[bytes(&id), h_ua(&to), i128v(700), bytes(&pay_ref), ScVal::U64(vu), addr(&lane0)]);
    let args = json!({"from": ua, "to": {"Ua": ua0x(&to)}, "amount": "700", "pay_ref": ua0x(&pay_ref), "valid_until": vu, "relayer": lane0, "auth": MSIG.sign(&d, "metatx")});
    let pay = |job: i64| ua_job(job, &st.token, "ua_pay", args.clone(), vec![]);
    let seq = node.adapter.sequence(0).await.unwrap();
    let refused = async |job: i64, what: &str| {
        let (state, last) = node.run(0, pay(job)).await;
        println!("MA {what}: job {state}, reason {}", last["error"]);
        assert_eq!(state, "dead", "{what}: {last}");
        assert!(last["error"].as_str().unwrap().starts_with("simulation:"), "the chain's refusal: {last}");
        assert!(report_of(&node.state.lock().unwrap(), job, "signed").is_null(), "{what}: never signed");
        assert_eq!(view_i128(&st.token, "ua_balance", &["--ua", &hx(&id)]), 5_000, "{what}");
    };
    refused(910, "no slot accepted").await;
    assert_eq!(node.adapter.sequence(0).await.unwrap(), seq, "the lane's sequence is unchanged");

    let m = ms["memberships"].as_array().unwrap();
    let job = |n: i64, r: &Value, sig: &str| accept_job(n, st, &ua, &r["index"], sig, Value::Null, vec![]);
    let (s0, s1) = (m[0]["sig"].as_str().unwrap(), m[1]["sig"].as_str().unwrap());
    node.mined("accept_membership slot 0", 0, job(911, &m[0], s0)).await;
    assert!(member_accepted(st, &ua, 0) && !member_accepted(st, &ua, 1));
    refused(912, "one of two slots accepted").await;

    // a member's bad acceptance: one byte, refused by the chain, the slot stays out
    let bad = format!("{}{}", &s1[..s1.len() - 2], if s1.ends_with("00") { "01" } else { "00" });
    let (state, last) = node.run(0, job(913, &m[1], &bad)).await;
    println!("MA a flipped acceptance: job {state}, reason {}", last["error"]);
    assert_eq!(state, "dead", "{last}");
    assert!(!member_accepted(st, &ua, 1));

    node.mined("accept_membership slot 1", 0, job(914, &m[1], s1)).await;
    assert!(member_accepted(st, &ua, 1));
    let (state, last) = node.run(0, job(915, &m[1], s1)).await;
    println!("MA a repeat: job {state}, reason {}", last["error"]);
    assert_eq!(state, "dead", "{last}");
    assert!(report_of(&node.state.lock().unwrap(), 915, "signed").is_null(), "never signed");
    let before = view_i128(&st.token, "ua_balance", &["--ua", &hx(&to)]);
    node.mined("ua_pay by the msig, its two slots accepted", 0, pay(916)).await;
    assert_eq!(view_i128(&st.token, "ua_balance", &["--ua", &hx(&id)]), 4_300);
    assert_eq!(view_i128(&st.token, "ua_balance", &["--ua", &hx(&to)]), before + 700);
}

/// The `memberships` rows of `msig-classical`, unchanged, on a real host through the node: `evm-eoa` and `p256` by the chain with no relayer,
/// the two relayer-checked members on the lane's attestation over `attest_digest`, marked in state. And a `G…` member: no entry, the
/// simulation records its signature and the job dies unsent; its signed entry in `op.auth`, it accepts.
#[tokio::test]
#[ignore]
async fn e2e_soroban_ua_membership_rows_and_a_g_member() {
    let st = stack().await;
    let node = Node::new(st).await;
    let p: Value = serde_json::from_str(PORTABLE).unwrap();
    let rows = p["registrations"].as_array().unwrap();
    let by_name = |n: &str| rows.iter().find(|r| r["name"] == n).unwrap().clone();
    let lane0 = g(&key(0));
    for (i, n) in ["bls-bn254-minsig", "schnorr-bn254"].iter().enumerate() {
        ensure_registered(&node, st, 920 + i as i64, &by_name(n), json!(lane0)).await;
    }
    ensure_registered(&node, st, 922, &by_name("p256"), Value::Null).await;
    ensure_registered(&node, st, 923, &by_name("msig-classical"), Value::Null).await;
    let ua = by_name("msig-classical")["ua"].as_str().unwrap().to_string();
    let rows: Vec<&Value> = p["memberships"].as_array().unwrap().iter().filter(|r| r["msig"] == "msig-classical").collect();
    assert_eq!(rows.len(), 4);
    for (i, r) in rows.iter().enumerate() {
        let (index, sig) = (r["index"].as_u64().unwrap(), r["sig"].as_str().unwrap());
        let relayer_checked = ![0x0001, 0x0101].contains(&r["memberKind"].as_u64().unwrap());
        if relayer_checked {
            let (state, last) = node.run(0, accept_job(930 + i as i64, st, &ua, &r["index"], sig, Value::Null, vec![])).await;
            println!("MA {} no relayer: job {state}, reason {}", r["name"], last["error"]);
            assert!(state == "dead" && last["error"].as_str().unwrap().contains("needs a relayer"), "{last}");
        }
        let relayer = if relayer_checked { json!(lane0) } else { Value::Null };
        node.mined(&format!("accept_membership {}", r["name"]), 0, accept_job(940 + i as i64, st, &ua, &r["index"], sig, relayer, vec![])).await;
        assert!(member_accepted(st, &ua, index), "{}", r["name"]);
        let mark = view(&st.registry, "member_checked", &["--ua", ua.trim_start_matches("0x"), "--index", &index.to_string()]);
        println!("MA {}: member_checked {mark}", r["name"]);
        assert_eq!(mark.contains(&lane0), relayer_checked, "{mark}");
    }

    // CTR-UA-34 rule 4: the bytes of a slot accepted on the lane's word, read back from the chain, re-checked off chain as a client does
    let (kd_of, keys) = (|n: &str| unhex(by_name(n)["keyData"].as_str().unwrap()), |id: [u8; 32]| {
        let hexid = ua0x(&id);
        row_of(&p, &hexid).map(|r| (r["kind"].as_u64().unwrap() as u16, unhex(r["keyData"].as_str().unwrap())))
    });
    let classical_ua: [u8; 32] = unhex(&ua).try_into().unwrap();
    for r in &rows {
        let index = r["index"].as_u64().unwrap();
        let stored = view(&st.registry, "membership_sig_of", &["--ua", ua.trim_start_matches("0x"), "--index", &index.to_string()]);
        if [0x0001, 0x0101].contains(&r["memberKind"].as_u64().unwrap()) {
            assert_eq!(stored, "", "{}: the chain checked it", r["name"]);
            continue;
        }
        assert_eq!(format!("0x{stored}"), r["sig"].as_str().unwrap(), "{}: the row's bytes", r["name"]);
        let slot = MemberSig { index: index as u16, key_data: vec![], sig: unhex(&stored) };
        check_membership(&kd_of("msig-classical"), &classical_ua, &slot, &keys).unwrap_or_else(|e| panic!("{}: {e:?}", r["name"]));
    }

    // a bad signature in the record: the node refuses it, a listed relayer's own transaction does not need the node, the chain reads no
    // byte of it, and the same re-check finds it out
    let (bls, sch) = (by_name("bls-bn254-minsig"), by_name("schnorr-bn254"));
    let mut list = [(0x0107u16, <[u8; 32]>::try_from(unhex(bls["ua"].as_str().unwrap())).unwrap(), 1u16), (0x0104, unhex(sch["ua"].as_str().unwrap()).try_into().unwrap(), 1)];
    list.sort_by_key(|m| m.1);
    let bad_kd = scaas_ua::encode_msig(1, &list);
    let bad_id = scaas_ua::ua_of(0x0120, &bad_kd).unwrap();
    let structure = json!({"name": "msig-junk", "ua": ua0x(&bad_id), "kind": 0x0120, "threshold": 1,
                           "members": list.iter().map(|m| json!({"kind": m.0, "id": ua0x(&m.1), "weight": 1})).collect::<Vec<_>>()});
    ensure_registered(&node, st, 924, &structure, Value::Null).await;
    let junk = ua0x(&[0x5a; 32]);
    let (state, last) = node.run(0, accept_job(925, st, &ua0x(&bad_id), &json!(0), &junk, json!(lane0), vec![])).await;
    println!("MA junk through the node: job {state}, reason {}", last["error"]);
    assert_eq!(state, "dead", "{last}");
    let slot_json = format!("{{\"index\":0,\"key_data\":\"\",\"sig\":\"{}\"}}", junk.trim_start_matches("0x"));
    send("accept_membership junk on a listed relayer's own word", 0, &st.registry, "accept_membership", &["--ua", &hx(&bad_id), "--member_sig", &slot_json, "--relayer", &format!("\"{lane0}\"")]).await;
    assert!(member_accepted(st, &ua0x(&bad_id), 0), "the mark says whose word it is, not that it is good");
    let stored = view(&st.registry, "membership_sig_of", &["--ua", &hx(&bad_id), "--index", "0"]);
    assert_eq!(format!("0x{stored}"), junk);
    let slot = MemberSig { index: 0, key_data: vec![], sig: unhex(&stored) };
    let e = check_membership(&bad_kd, &bad_id, &slot, &keys).unwrap_err();
    println!("MA junk in the record, re-checked off chain: {e:?}");
    assert_eq!(e, scaas_ua::UAError::Unauthorized);

    let member = key(BYSTANDER);
    fund(&g(&member)).await;
    let gid: [u8; 32] = member.public_key().try_into().unwrap();
    let kd = scaas_ua::encode_msig(1, &[(0x0011, gid, 1)]);
    let id = scaas_ua::ua_of(0x0120, &kd).unwrap();
    let structure = json!({"name": "msig-g", "ua": ua0x(&id), "kind": 0x0120, "threshold": 1, "members": [{"kind": 0x0011, "id": ua0x(&gid), "weight": 1}]});
    ensure_registered(&node, st, 950, &structure, Value::Null).await;
    let gua = ua0x(&id);
    let (state, last) = node.run(0, accept_job(951, st, &gua, &json!(0), "0x", Value::Null, vec![])).await;
    println!("MA G member, no entry: job {state}, reason {}", last["error"]);
    assert_eq!(state, "dead", "{last}");
    assert!(report_of(&node.state.lock().unwrap(), 951, "signed").is_null(), "never signed");
    let tag = scaas_ua::purpose_tag("membership").unwrap();
    let root = invocation(&st.registry, "accept_membership", vec![bytes(&id), bytes(&tag), bytes(&scaas_ua::ua8::membership_digest(&id, &gid))], vec![]);
    let nonce = i64::from_be_bytes(fresh()[..8].try_into().unwrap());
    let (payload, signature) = signed_auth(&member, nonce, latest_ledger().await as u32 + 1_000, &root);
    let auth = vec![json!({"payload": payload, "from": g(&member), "signature": signature})];
    node.mined("accept_membership a G member, relayed", 1, accept_job(952, st, &gua, &json!(0), "0x", Value::Null, auth)).await;
    assert!(member_accepted(st, &gua, 0));
}

/// A DEX `settle` of two native makers through `lane_step`: named orders, two `op.auth` entries and the lane's own entry.
#[tokio::test]
#[ignore]
async fn e2e_soroban_dex_both_native() {
    let st = stack().await;
    let node = Node::new(st).await;
    let (maker, taker, lane0) = (key(BYSTANDER), key(TAKER), g(&key(0)));
    fund(&g(&maker)).await;
    let (mg, tg) = (g(&maker), g(&taker));
    send("set_market (fees off)", DEPLOYER, &st.dex, "set_market", &["--token_a", &st.token, "--token_b", &st.token_b, "--market",
         "{\"fee_on\":false,\"maker_fee_ppm\":0,\"taker_fee_ppm\":0}"]).await;
    send("mint (maker, token A)", DEPLOYER, &st.token, "mint", &["--to", &mg, "--amount", "10000"]).await;
    send("mint (taker, token B)", DEPLOYER, &st.token_b, "mint", &["--to", &tg, "--amount", "20000"]).await;
    let ledger = latest_ledger().await;
    let exp = (ledger + 5_000).to_string();
    send("approve (maker -> DEX, token A)", BYSTANDER, &st.token, "approve", &["--from", &mg, "--spender", &st.dex, "--amount", "10000", "--expiration_ledger", &exp]).await;
    send("approve (taker -> DEX, token B)", TAKER, &st.token_b, "approve", &["--from", &tg, "--spender", &st.dex, "--amount", "20000", "--expiration_ledger", &exp]).await;

    let expiry = now() + 600;
    let salt = u64::from_be_bytes(fresh()[..8].try_into().unwrap());
    let a = order(h_addr(&mg), h_addr(&mg), &lane0, &st.token, 1_000, &st.token_b, 2_000, expiry, salt);
    let b = order(h_addr(&tg), h_addr(&tg), &lane0, &st.token_b, 2_000, &st.token, 1_000, expiry, salt);
    let nonce = || i64::from_be_bytes(fresh()[..8].try_into().unwrap());
    let (pa, sa) = signed_auth(&maker, nonce(), ledger as u32 + 1_000, &settle_root(&st.dex, &a));
    let (pb, sb) = signed_auth(&taker, nonce(), ledger as u32 + 1_000, &settle_root(&st.dex, &b));
    let auth = vec![json!({"payload": pa, "from": mg, "signature": sa}), json!({"payload": pb, "from": tg, "signature": sb})];

    let bal = |t: &str, id: &str| view_i128(t, "balance", &["--id", id]);
    let (ma, tb) = (bal(&st.token, &mg), bal(&st.token_b, &tg));
    let args = json!({"maker": order_json(&json!({"Addr": mg}), &lane0, &st.token, 1_000, &st.token_b, 2_000, expiry, salt),
                      "taker": order_json(&json!({"Addr": tg}), &lane0, &st.token_b, 2_000, &st.token, 1_000, expiry, salt),
                      "maker_fill": "1000", "maker_auth": no_auth(), "taker_auth": no_auth()});
    node.mined("settle, two native makers", 0, ua_job(801, &st.dex, "settle", args, auth)).await;
    assert_eq!(bal(&st.token, &mg), ma - 1_000);
    assert_eq!(bal(&st.token_b, &tg), tb - 2_000);
    assert_eq!(bal(&st.token, &st.dex), 0, "the DEX holds nothing after the settle");
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
    let approve = json!([{"type": "Address", "value": lane0}, {"type": "Address", "value": by}, {"type": "i128", "value": "1000000"}, {"type": "u32", "value": ledger + 1_000}]);
    let args = json!({"payer": ua0x(&pk), "target": st.token, "func": "approve", "args": approve, "salt": ua0x(&salt), "token": st.token,
                      "to": {"Addr": st.router}, "amount": fee.to_string(), "valid_until": vu, "relayer": lane0, "auth": PASSKEY.sign(&d, "metatx")});
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
