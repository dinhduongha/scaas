//! UA-8 on Soroban (plan ua8-soroban B7, C15): a UA record copied EVM → Soroban → EVM byte for byte on a real Protocol 30
//! host and two anvil chains, and what only a real host can answer. `smartcontracts/soroban/scripts/e2e-ua8-local.sh` runs it
//! (env: see `soroban_common`, `UA8_EVM_A` / `UA8_EVM_B` = `<chain id>,<rpc url>`); `#[ignore]`, one test at a time.
//!
//! Every comparison is between independent sources: a chain's read against the vector or against the other chain's read,
//! never a value against its own copy. The registry writes go through the node's `call` jobs (`lane_step` on Soroban, the
//! outbox on EVM); only the published byte limits of `e2e_ua8_network_fit` use `raw_send`, junk `slhdsa128s` signatures the
//! off-chain check would refuse and the chain never reads. Log prefixes: `COPY`, `FIT`, `EDGE`, `P1` … `P5` (the brief's proofs).
mod soroban_common;

use std::process::Command;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use alloy::network::EthereumWallet;
use alloy::primitives::{Address, Bytes, B256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolCall;
use ml_dsa::signature::Keypair as _;
use ml_dsa::{MlDsa65, Seed, SigningKey};
use pqcrypto_falcon::falconpadded512 as falcon;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
use scaas_node::adapter::{lane_step, Built, ChainAdapter};
use scaas_node::adapters::soroban::{ua8_call_job, SorobanAdapter};
use scaas_node::chain::Chain;
use scaas_node::config::{ChainCfg, FinalityCfg};
use scaas_node::odoo::Odoo;
use scaas_node::signer::Signer;
use scaas_node::submit::Submitter;
use scaas_ua::ua8::{self, decode_member_sigs, encode_member_sigs, KemKey, MemberSig, MsigStructure, UAAttrs};
use serde_json::{json, Value};
use soroban_common::*;
use stellar_xdr::{
    DiagnosticEvent, HostFunction, InvokeContractArgs, InvokeHostFunctionOp, LedgerEntryData, LedgerKey, Limits, Memo, MuxedAccount, Operation,
    OperationBody, Preconditions, ReadXdr, ScAddress, ScSymbol, ScVal, SequenceNumber, SorobanAuthorizationEntry, SorobanTransactionData,
    Transaction, TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256, WriteXdr,
};
use tokio::sync::{Mutex as AsyncMutex, OnceCell};

const PORTABLE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../smartcontracts/vectors/ua/portable.json"));
const ROUND_TRIP: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../smartcontracts/soroban/vectors/ua8-roundtrip.json"));
const EVM_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../smartcontracts/evm");
/// anvil's first two accounts: the deployer and client of chain A, the node's EVM lane on chain B.
const DEPLOYER_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const DEPLOYER_ADDRESS: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const LANE_KEY: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const SETS: [&str; 4] = ["n2048-kmax1024", "n2304-kmax4096", "n2560-kmax16384", "n2816-kmax65536"];
/// `soroban_common::key` indexes: lanes 0 and 1, the deployer, a `G…` member.
const DEPLOYER: u32 = 7;
const BYSTANDER: u32 = 8;
const MSIG: u16 = 0x0120;
const MLDSA65: u16 = 0x0131;
const FNDSA512: u16 = 0x0132;
const SLHDSA128S: u16 = 0x0133;
const STELLAR_ACCOUNT: u16 = 0x0011;

alloy::sol! {
    struct SolKem { uint8 scheme; bytes mlkemEk; bytes32 x25519; }
    struct SolAttrs { bytes pqzKey; bytes32 pqzPopHash; SolKem kem; bytes32 kemPkHash; }
    struct SolMember { uint16 kind; bytes32 id; uint16 weight; }
    struct SolStructure { uint16 threshold; SolMember[] members; }
    struct SolMemberSig { uint16 index; bytes keyData; bytes sig; }
    struct SolSig { bytes keyData; bytes signature; SolMemberSig[] members; }
    function cacheExpandedKey(uint16 kind, bytes pk, uint256 part) external returns (bytes32 ua);
    function register(uint16 kind, bytes keyData, SolAttrs attrs, bytes pop, bytes pqzPop) external returns (bytes32);
    function registerMsig(SolStructure structure, SolAttrs attrs, SolMemberSig[] pop, bytes pqzPop) external returns (bytes32);
    function setKemKey(bytes32 ua, uint64 version, SolKem kem, SolSig sig) external;
    function storePqzPop(bytes32 ua, bytes pqzPop) external;
    function setPqzKey(bytes32 ua, bytes pqzKey, bytes32 pqzPopHash, SolSig sig) external;
    function registrationOf(bytes32 ua) external view returns (uint16 kind, bytes keyData, SolAttrs attrs, bytes pop, bytes pqzPop);
    function kemKeyAt(bytes32 ua, uint64 version) external view returns (SolKem kem, bytes sig);
    function kemKeyOf(bytes32 ua) external view returns (uint64 version, SolKem kem, bytes sig);
    function pqzKeyOf(bytes32 ua) external view returns (address ptr, bytes32 pqzPopHash, bool proven);
    function pqzKeySigOf(bytes32 ua) external view returns (bytes);
    function pqzPopOf(bytes32 ua) external view returns (bytes);
}

// ---------- values ----------

fn h(b: &[u8]) -> String {
    format!("0x{}", alloy::hex::encode(b))
}

fn hx(v: &Value) -> Vec<u8> {
    alloy::hex::decode(v.as_str().unwrap()).unwrap()
}

fn hx32(v: &Value) -> [u8; 32] {
    hx(v).try_into().unwrap()
}

fn portable() -> Value {
    serde_json::from_str(PORTABLE).unwrap()
}

fn row(list: &str, name: &str) -> Value {
    portable()[list].as_array().unwrap().iter().find(|r| r["name"] == name || r["id"] == name).cloned().unwrap()
}

/// `ua8-roundtrip.json`'s line of a row: what the unit host answered, in the order it wrote.
fn round_trip(name: &str) -> Value {
    let v: Value = serde_json::from_str(ROUND_TRIP).unwrap();
    v["rows"].as_array().unwrap().iter().find(|r| r["name"] == name).cloned().unwrap()
}

/// `a` and `b` byte for byte; a difference names the field and the first offset, not 60 KB of hex.
fn same(what: &str, field: &str, a: &[u8], b: &[u8]) {
    if a != b {
        panic!("{what}: {field} differs: {} B and {} B, first at {:?}", a.len(), b.len(), a.iter().zip(b).position(|(x, y)| x != y));
    }
}

/// The five `register` arguments, read from one source.
#[derive(Clone)]
struct Rec {
    kind: u16,
    key_data: Vec<u8>,
    attrs: UAAttrs,
    pop: Vec<u8>,
    pqz_pop: Vec<u8>,
}

fn kem_of_row(k: &Value) -> KemKey {
    KemKey { scheme: k["scheme"].as_u64().unwrap() as u8, mlkem_ek: hx(&k["mlkemEk"]), x25519: hx32(&k["x25519"]) }
}

fn kem_eq(what: &str, a: &KemKey, b: &KemKey) {
    same(what, "kem.scheme", &[a.scheme], &[b.scheme]);
    same(what, "kem.mlkem_ek", &a.mlkem_ek, &b.mlkem_ek);
    same(what, "kem.x25519", &a.x25519, &b.x25519);
}

impl Rec {
    fn of_row(r: &Value) -> Rec {
        let a = &r["args"]["attrs"];
        let attrs = UAAttrs { pqz_key: hx(&a["pqzKey"]), pqz_pop_hash: hx32(&a["pqzPopHash"]), kem: kem_of_row(&a["kem"]), kem_pk_hash: hx32(&a["kemPkHash"]) };
        Rec { kind: r["kind"].as_u64().unwrap() as u16, key_data: hx(&r["keyData"]), attrs, pop: hx(&r["pop"]), pqz_pop: hx(&r["pqzPop"]) }
    }

    fn of_soroban(v: &ScVal) -> Rec {
        let ScVal::Vec(Some(t)) = v else { panic!("registration_of: {v:?}") };
        let ScVal::U32(kind) = t[0] else { panic!("kind: {:?}", t[0]) };
        let a = &t[2];
        let attrs = UAAttrs { pqz_key: by(field(a, "pqz_key")), pqz_pop_hash: by32(field(a, "pqz_pop_hash")), kem: kem_sc(field(a, "kem")), kem_pk_hash: by32(field(a, "kem_pk_hash")) };
        Rec { kind: kind as u16, key_data: by(&t[1]), attrs, pop: by(&t[3]), pqz_pop: by(&t[4]) }
    }

    fn eq(&self, what: &str, o: &Rec) {
        same(what, "kind", &self.kind.to_be_bytes(), &o.kind.to_be_bytes());
        same(what, "key_data", &self.key_data, &o.key_data);
        same(what, "attrs.pqz_key", &self.attrs.pqz_key, &o.attrs.pqz_key);
        same(what, "attrs.pqz_pop_hash", &self.attrs.pqz_pop_hash, &o.attrs.pqz_pop_hash);
        kem_eq(what, &self.attrs.kem, &o.attrs.kem);
        same(what, "attrs.kem_pk_hash", &self.attrs.kem_pk_hash, &o.attrs.kem_pk_hash);
        same(what, "pop", &self.pop, &o.pop);
        same(what, "pqz_pop", &self.pqz_pop, &o.pqz_pop);
    }

    fn ua(&self) -> [u8; 32] {
        scaas_ua::ua_of(self.kind, &self.key_data).unwrap()
    }

    /// The Soroban `call` job's function and arguments.
    fn job_args(&self, relayer: &Value) -> (&'static str, Value) {
        let (a, pqz_pop) = (attrs_json(&self.attrs), h(&self.pqz_pop));
        if self.kind == MSIG {
            let s = MsigStructure::from_key_data(&self.key_data).unwrap();
            let members: Vec<Value> = s.members.iter().map(|m| json!({"kind": m.kind, "id": h(&m.id), "weight": m.weight})).collect();
            let pop = member_sigs_json(&decode_member_sigs(&self.pop).unwrap_or_default());
            ("register_msig", json!({"structure": {"threshold": s.threshold, "members": members}, "attrs": a, "pop": pop, "pqz_pop": pqz_pop, "relayer": relayer}))
        } else {
            ("register", json!({"kind": self.kind, "key_data": h(&self.key_data), "attrs": a, "pop": h(&self.pop), "pqz_pop": pqz_pop, "relayer": relayer}))
        }
    }

    /// EVM's `register` / `registerMsig` calldata, without the proof (the node's split rule: `storePqzPop` follows).
    fn calldata(&self) -> Vec<u8> {
        let (attrs, none) = (sol_attrs(&self.attrs), Bytes::new());
        if self.kind == MSIG {
            let s = MsigStructure::from_key_data(&self.key_data).unwrap();
            let members = s.members.iter().map(|m| SolMember { kind: m.kind, id: m.id.into(), weight: m.weight }).collect();
            let pop = sol_member_sigs(&decode_member_sigs(&self.pop).unwrap_or_default());
            registerMsigCall { structure: SolStructure { threshold: s.threshold, members }, attrs, pop, pqzPop: none }.abi_encode()
        } else {
            registerCall { kind: self.kind, keyData: self.key_data.clone().into(), attrs, pop: self.pop.clone().into(), pqzPop: none }.abi_encode()
        }
    }
}

fn attrs_json(a: &UAAttrs) -> Value {
    json!({"pqz_key": h(&a.pqz_key), "pqz_pop_hash": h(&a.pqz_pop_hash), "kem": kem_json(&a.kem), "kem_pk_hash": h(&a.kem_pk_hash)})
}

fn kem_json(k: &KemKey) -> Value {
    json!({"scheme": k.scheme, "mlkem_ek": h(&k.mlkem_ek), "x25519": h(&k.x25519)})
}

fn member_sigs_json(m: &[MemberSig]) -> Vec<Value> {
    m.iter().map(|s| json!({"index": s.index, "key_data": h(&s.key_data), "sig": h(&s.sig)})).collect()
}

/// A stored portable signature (`signature`, or an `msig`'s `abi.encode(MemberSig[])`) as the job's `sig`.
fn sig_json(kind: u16, stored: &[u8]) -> Value {
    if kind == MSIG {
        json!({"key_data": "0x", "signature": "0x", "members": member_sigs_json(&decode_member_sigs(stored).unwrap())})
    } else {
        json!({"key_data": "0x", "signature": h(stored), "members": []})
    }
}

fn sol_kem(k: &KemKey) -> SolKem {
    SolKem { scheme: k.scheme, mlkemEk: k.mlkem_ek.clone().into(), x25519: k.x25519.into() }
}

fn sol_attrs(a: &UAAttrs) -> SolAttrs {
    SolAttrs { pqzKey: a.pqz_key.clone().into(), pqzPopHash: a.pqz_pop_hash.into(), kem: sol_kem(&a.kem), kemPkHash: a.kem_pk_hash.into() }
}

fn sol_member_sigs(m: &[MemberSig]) -> Vec<SolMemberSig> {
    m.iter().map(|s| SolMemberSig { index: s.index, keyData: s.key_data.clone().into(), sig: s.sig.clone().into() }).collect()
}

fn sol_sig(kind: u16, stored: &[u8]) -> SolSig {
    if kind == MSIG {
        SolSig { keyData: Bytes::new(), signature: Bytes::new(), members: sol_member_sigs(&decode_member_sigs(stored).unwrap()) }
    } else {
        SolSig { keyData: Bytes::new(), signature: stored.to_vec().into(), members: vec![] }
    }
}

fn kem_sol(k: &SolKem) -> KemKey {
    KemKey { scheme: k.scheme, mlkem_ek: k.mlkemEk.to_vec(), x25519: k.x25519.0 }
}

// ---------- Soroban reads and raw transactions ----------

fn sc(s: &str) -> ScAddress {
    s.parse().unwrap()
}

fn sc_bytes(b: &[u8]) -> ScVal {
    ScVal::Bytes(b.to_vec().try_into().unwrap())
}

fn sym(s: &str) -> ScSymbol {
    ScSymbol(s.try_into().unwrap())
}

fn by(v: &ScVal) -> Vec<u8> {
    match v {
        ScVal::Bytes(b) => b.to_vec(),
        _ => panic!("not bytes: {v:?}"),
    }
}

fn by32(v: &ScVal) -> [u8; 32] {
    by(v).try_into().unwrap()
}

fn tuple(v: &ScVal) -> &[ScVal] {
    match v {
        ScVal::Vec(Some(t)) => t,
        _ => panic!("not a tuple: {v:?}"),
    }
}

fn field<'a>(v: &'a ScVal, k: &str) -> &'a ScVal {
    let ScVal::Map(Some(m)) = v else { panic!("not a struct: {v:?}") };
    &m.iter().find(|e| matches!(&e.key, ScVal::Symbol(s) if s.0.as_slice() == k.as_bytes())).unwrap_or_else(|| panic!("no field {k}")).val
}

fn kem_sc(v: &ScVal) -> KemKey {
    let ScVal::U32(scheme) = field(v, "scheme") else { panic!("scheme") };
    KemKey { scheme: *scheme as u8, mlkem_ek: by(field(v, "mlkem_ek")), x25519: by32(field(v, "x25519")) }
}

/// A `Checked` as `portable.json` codes it, and the relayer it names.
fn checked(v: &ScVal) -> (u64, Option<String>) {
    let t = tuple(v);
    match (&t[0], t.get(1)) {
        (ScVal::Symbol(s), None) if s.0.as_slice() == b"None" => (0, None),
        (ScVal::Symbol(s), None) if s.0.as_slice() == b"Chain" => (1, None),
        (ScVal::Symbol(s), Some(ScVal::Address(a))) if s.0.as_slice() == b"Relayer" => (2, Some(a.to_string())),
        _ => panic!("not a Checked: {v:?}"),
    }
}

fn op(call: InvokeContractArgs, auth: Vec<SorobanAuthorizationEntry>) -> Operation {
    Operation { source_account: None, body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp { host_function: HostFunction::InvokeContract(call), auth: auth.try_into().unwrap() }) }
}

fn tx(lane: u32, seq: i64, fee: u32, call: InvokeContractArgs, auth: Vec<SorobanAuthorizationEntry>, ext: TransactionExt) -> Transaction {
    Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(key(lane).public_key().try_into().unwrap())),
        fee,
        seq_num: SequenceNumber(seq),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![op(call, auth)].try_into().unwrap(),
        ext,
    }
}

/// `simulateTransaction` of `call` by `lane`, as the node sends it, the whole JSON-RPC answer (`extra` = more parameters).
async fn simulate_rpc(lane: u32, call: InvokeContractArgs, auth: Vec<SorobanAuthorizationEntry>, extra: Value) -> Value {
    let env = TransactionEnvelope::Tx(TransactionV1Envelope { tx: tx(lane, 0, 100, call, auth, TransactionExt::V0), signatures: Default::default() });
    let mut params = json!({"transaction": env.to_xdr_base64(Limits::none()).unwrap()});
    params.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "simulateTransaction", "params": params});
    reqwest::Client::new().post(rpc_url()).json(&body).send().await.unwrap().json().await.unwrap()
}

async fn simulate(lane: u32, call: InvokeContractArgs, auth: Vec<SorobanAuthorizationEntry>) -> Value {
    simulate_rpc(lane, call, auth, json!({})).await["result"].clone()
}

/// A view of `contract` by simulation, as XDR: no JSON rendering between the state and the bytes compared.
async fn read(contract: &str, f: &str, args: Vec<ScVal>) -> ScVal {
    let call = InvokeContractArgs { contract_address: sc(contract), function_name: sym(f), args: args.try_into().unwrap() };
    let r = simulate(0, call, vec![]).await;
    assert!(r.get("error").is_none(), "{f}: {}", r["error"]);
    ScVal::from_xdr_base64(r["results"][0]["xdr"].as_str().unwrap(), Limits::none()).unwrap()
}

/// The landed envelope's invoke operation.
fn landed_op(env: &TransactionEnvelope) -> (&Transaction, &InvokeHostFunctionOp) {
    let TransactionEnvelope::Tx(e) = env else { panic!("not a v1 envelope") };
    let OperationBody::InvokeHostFunction(o) = &e.tx.operations[0].body else { panic!("not an invoke") };
    (&e.tx, o)
}

/// The transaction landed or failed: its `getTransaction` answer.
async fn await_tx(hash: &str) -> Value {
    for _ in 0..120 {
        let r = rpc("getTransaction", json!({"hash": hash.trim_start_matches("0x")})).await;
        if r["status"] != "NOT_FOUND" {
            return r;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("{hash}: never landed");
}

/// `core_metrics` of a landed transaction (the diagnostic events core writes): `(name, value)`; empty when the node has none.
fn core_metrics(r: &Value) -> Vec<(String, u64)> {
    let xs: Vec<&Value> = [&r["diagnosticEventsXdr"], &r["events"]["diagnosticEventsXdr"]].into_iter().filter_map(|v| v.as_array()).flatten().collect();
    let mut out = vec![];
    for x in xs {
        let Ok(e) = DiagnosticEvent::from_xdr_base64(x.as_str().unwrap_or_default(), Limits::none()) else { continue };
        let stellar_xdr::ContractEventBody::V0(b) = &e.event.body;
        if let ([ScVal::Symbol(a), ScVal::Symbol(n)], ScVal::U64(v)) = (b.topics.as_slice(), &b.data) {
            if a.0.as_slice() == b"core_metrics" {
                out.push((String::from_utf8_lossy(n.0.as_slice()).into_owned(), *v));
            }
        }
    }
    out
}

/// One line per landed transaction, on the network's limits; `FIT …` for the report's table.
async fn fit(what: &str, hash: &str) {
    let r = await_tx(hash).await;
    assert_eq!(r["status"], "SUCCESS", "{what}: {r}");
    let raw = r["envelopeXdr"].as_str().unwrap();
    let env = TransactionEnvelope::from_xdr_base64(raw, Limits::none()).unwrap();
    let (tx, _) = landed_op(&env);
    let TransactionExt::V1(data) = &tx.ext else { panic!("no Soroban data") };
    let f = &data.resources.footprint;
    let keys: Vec<String> = f.read_write.iter().map(|k: &LedgerKey| k.to_xdr_base64(Limits::none()).unwrap()).collect();
    let got = rpc("getLedgerEntries", json!({"keys": keys})).await;
    let largest = got["entries"].as_array().into_iter().flatten()
        .map(|e| LedgerEntryData::from_xdr_base64(e["xdr"].as_str().unwrap(), Limits::none()).unwrap().to_xdr(Limits::none()).unwrap().len())
        .max().unwrap_or(0);
    let m = core_metrics(&r);
    let metric = |n: &str| m.iter().find(|x| x.0 == n).map_or("n/a".to_string(), |x| x.1.to_string());
    let res = stellar_xdr::TransactionResult::from_xdr_base64(r["resultXdr"].as_str().unwrap(), Limits::none()).unwrap();
    let size = env.to_xdr(Limits::none()).unwrap().len();
    println!(
        "FIT {what}: cpu_insns {} used_cpu {} mem_bytes {} read_bytes {} write_bytes {} entries {} writes {} tx_size {size} largest_entry {largest} events_bytes {} resource_fee {} fee_charged {}",
        data.resources.instructions, metric("cpu_insn"), metric("mem_byte"), data.resources.disk_read_bytes, data.resources.write_bytes,
        f.read_only.len() + f.read_write.len(), f.read_write.len(), metric("emit_event_byte"), data.resource_fee, res.fee_charged
    );
}

// ---------- the node ----------

static JOB: AtomicI64 = AtomicI64::new(1_000);

/// A Soroban `call` job on `registry`.
fn call_job(registry: &str, f: &str, args: Value) -> Value {
    let id = JOB.fetch_add(1, Ordering::Relaxed);
    json!({"id": id, "kind": "call", "op": {"contract": registry, "function": f, "args": args, "valid_until": now() + 600}})
}

/// The node on one Soroban registry: the adapter over lanes 0 and 1, a fake Odoo.
struct Node {
    registry: String,
    state: Arc<Mutex<FakeOdoo>>,
    odoo: Odoo,
    adapter: SorobanAdapter,
}

impl Node {
    async fn new(registry: String) -> Node {
        Node::with_fee_bump(registry, false).await
    }

    async fn with_fee_bump(registry: String, fee_bump: bool) -> Node {
        let state = Arc::new(Mutex::new(FakeOdoo::default()));
        let odoo = odoo_at(start_fake(state.clone()).await);
        let mut cfg = chain_cfg(fee_bump);
        cfg.params.insert("ua_registry".into(), registry.clone().into());
        let adapter = SorobanAdapter::new(&cfg, &[key(0), key(1)]).unwrap();
        Node { registry, state, odoo, adapter }
    }

    /// One `lane_step` of `job`: its final state, its last report and its transaction, when one was signed.
    async fn run(&self, lane: usize, job: Value) -> (String, Value, Option<String>) {
        let id = job["id"].as_i64().unwrap();
        self.state.lock().unwrap().jobs.push(job);
        assert!(lane_step(&self.adapter, &self.odoo, lane, &format!("ua8#{lane}")).await.unwrap());
        let o = self.state.lock().unwrap();
        assert!(o.refused.is_empty(), "{:?}", o.refused);
        let tx = report_of(&o, id, "signed")["tx_hash"].as_str().map(str::to_string);
        (last_state(&o, id), o.reports.iter().rev().find(|r| r["job_id"] == id).cloned().unwrap_or_default(), tx)
    }

    /// `f` through a `call` job, expecting `mined`: the transaction, its `FIT` line logged.
    async fn mined(&self, what: &str, f: &str, args: Value) -> String {
        let (state, last, tx) = self.run(0, call_job(&self.registry, f, args)).await;
        assert_eq!(state, "mined", "{what}: {last}");
        let tx = tx.unwrap();
        fit(what, &tx).await;
        tx
    }

    /// A transaction the node's checks do not see: `ua8_call_job`'s XDR, simulated as `build` does, sent if it simulates.
    /// `Err` is the refusal, at simulation or on chain.
    async fn raw_send(&self, what: &str, lane: usize, call: InvokeContractArgs, auth: Vec<SorobanAuthorizationEntry>) -> Result<String, String> {
        let sim = simulate(lane as u32, call.clone(), auth.clone()).await;
        if let Some(e) = sim.get("error") {
            return Err(format!("simulation: {}", e.as_str().unwrap_or_default().chars().take(240).collect::<String>()));
        }
        let mut data = SorobanTransactionData::from_xdr_base64(sim["transactionData"].as_str().unwrap(), Limits::none()).unwrap();
        data.resource_fee += data.resource_fee * 15 / 100;
        let t = tx(lane as u32, 0, 100 + data.resource_fee as u32, call, auth, TransactionExt::V1(data));
        let seq = self.adapter.sequence(lane).await.unwrap();
        let built = Built { job_id: 0, body: t.to_xdr(Limits::none()).unwrap(), valid_until: 0, meta: json!({}) };
        let signed = self.adapter.sign(built, lane, seq).await.unwrap();
        self.adapter.submit(&signed).await.map_err(|e| format!("sendTransaction: {e:#}"))?;
        let r = await_tx(&signed.tx_id).await;
        if r["status"] != "SUCCESS" {
            return Err(format!("on chain: {} {}", r["status"], r["resultXdr"]));
        }
        fit(what, &signed.tx_id).await;
        Ok(signed.tx_id)
    }

    async fn rec(&self, ua: &[u8; 32]) -> Rec {
        Rec::of_soroban(&read(&self.registry, "registration_of", vec![sc_bytes(ua)]).await)
    }

    /// `checked_of`: `(pop, pqz_pop, kem)`.
    async fn checked_of(&self, ua: &[u8; 32]) -> [(u64, Option<String>); 3] {
        let v = read(&self.registry, "checked_of", vec![sc_bytes(ua)]).await;
        let t = tuple(&v);
        [checked(&t[0]), checked(&t[1]), checked(&t[2])]
    }

    async fn kem_at(&self, ua: &[u8; 32], version: u64) -> (KemKey, Vec<u8>, (u64, Option<String>)) {
        let v = read(&self.registry, "kem_key_at", vec![sc_bytes(ua), ScVal::U64(version)]).await;
        let t = tuple(&v);
        (kem_sc(&t[0]), by(&t[1]), checked(&t[2]))
    }

    async fn kem_max(&self, ua: &[u8; 32]) -> u64 {
        let v = read(&self.registry, "kem_key_of", vec![sc_bytes(ua)]).await;
        match tuple(&v)[0] {
            ScVal::U64(x) => x,
            _ => panic!("{v:?}"),
        }
    }
}

/// A fresh registry, lanes 0 and 1 listed, and the node on it.
async fn fresh_node() -> Node {
    for i in [0, 1, DEPLOYER, BYSTANDER] {
        fund(&g(&key(i))).await;
    }
    let relayers = format!("[\"{}\",\"{}\"]", g(&key(0)), g(&key(1)));
    Node::new(deploy_sh("ua_registry", &secret(DEPLOYER), &["--relayers", &relayers])).await
}

// ---------- EVM ----------

struct Evm {
    id: u64,
    rpc: String,
    registry: Address,
}

fn evm_of(env_name: &str) -> (u64, String) {
    let v = std::env::var(env_name).unwrap_or_else(|_| panic!("{env_name} = <chain id>,<rpc url> (e2e-ua8-local.sh sets it)"));
    let (id, rpc) = v.split_once(',').unwrap();
    (id.parse().unwrap(), rpc.to_string())
}

/// `script/Deploy.s.sol` on an anvil of the script's: the registry with every kind the chain runs (`DeployBase`).
fn deploy_evm(id: u64, rpc: &str) -> Address {
    let st = Command::new("forge")
        .current_dir(EVM_DIR)
        .args(["script", "script/Deploy.s.sol", "--rpc-url", rpc, "--broadcast", "--slow", "--silent", "--disable-code-size-limit", "--sender", DEPLOYER_ADDRESS])
        .env("PRIVATE_KEY", DEPLOYER_KEY)
        .env("FOUNDRY_PROFILE", "scaas-testnet")
        .status()
        .expect("forge in PATH");
    assert!(st.success(), "forge script on chain {id}");
    let dep: Value = serde_json::from_str(&std::fs::read_to_string(format!("{EVM_DIR}/deployments/{id}.json")).unwrap()).unwrap();
    dep["ua_registry"].as_str().unwrap().parse().unwrap()
}

impl Evm {
    async fn up(env_name: &str) -> Evm {
        let (id, rpc) = evm_of(env_name);
        let registry = deploy_evm(id, &rpc);
        println!("COPY evm chain {id}: registry {registry:#x}");
        Evm { id, rpc, registry }
    }

    async fn view<C: SolCall>(&self, c: C) -> C::Return {
        let p = ProviderBuilder::new().connect_http(self.rpc.parse().unwrap());
        C::abi_decode_returns(&p.call(TransactionRequest::default().to(self.registry).input(c.abi_encode().into())).await.unwrap()).unwrap()
    }

    /// A client's own transaction (chain A), its gas logged.
    async fn send(&self, what: &str, data: Vec<u8>) {
        let from: PrivateKeySigner = DEPLOYER_KEY.parse().unwrap();
        let p = ProviderBuilder::new().wallet(EthereumWallet::from(from)).connect_http(self.rpc.parse().unwrap());
        let r = p.send_transaction(TransactionRequest::default().to(self.registry).input(data.into())).await.unwrap().get_receipt().await.unwrap();
        assert!(r.status(), "{what}");
        println!("COPY evm {} {what}: gas_used {}", self.id, r.gas_used);
    }

    /// ML-DSA-65's two `cacheExpandedKey` parts, which EVM verifies on (P6c).
    async fn cache_key(&self, name: &str, pk: &[u8]) {
        for part in 0..2u64 {
            self.send(&format!("cacheExpandedKey {name} part {part}"), cacheExpandedKeyCall { kind: MLDSA65, pk: pk.to_vec().into(), part: part.try_into().unwrap() }.abi_encode()).await;
        }
    }

    async fn rec(&self, ua: &[u8; 32]) -> Rec {
        let r = self.view(registrationOfCall { ua: ua.into() }).await;
        let a = r.attrs;
        let attrs = UAAttrs { pqz_key: a.pqzKey.to_vec(), pqz_pop_hash: a.pqzPopHash.0, kem: kem_sol(&a.kem), kem_pk_hash: a.kemPkHash.0 };
        Rec { kind: r.kind, key_data: r.keyData.to_vec(), attrs, pop: r.pop.to_vec(), pqz_pop: r.pqzPop.to_vec() }
    }

    async fn kem_at(&self, ua: &[u8; 32], version: u64) -> (KemKey, Vec<u8>) {
        let r = self.view(kemKeyAtCall { ua: ua.into(), version }).await;
        (kem_sol(&r.kem), r.sig.to_vec())
    }

    async fn kem_max(&self, ua: &[u8; 32]) -> u64 {
        self.view(kemKeyOfCall { ua: ua.into() }).await.version
    }

    /// `(key, pqz_pop_hash, sig)` of a `setPqzKey` key: the key is the SSTORE2 pointer's code, past its STOP byte.
    async fn pqz(&self, ua: &[u8; 32]) -> (Vec<u8>, [u8; 32], Vec<u8>) {
        let k = self.view(pqzKeyOfCall { ua: ua.into() }).await;
        let p = ProviderBuilder::new().connect_http(self.rpc.parse().unwrap());
        let code = p.get_code_at(k.ptr).await.unwrap();
        (code[1..].to_vec(), k.pqzPopHash.0, self.view(pqzKeySigOfCall { ua: ua.into() }).await.to_vec())
    }

    async fn pqz_pop(&self, ua: &[u8; 32]) -> Vec<u8> {
        self.view(pqzPopOfCall { ua: ua.into() }).await.to_vec()
    }
}

/// Chain B's side of the node: EVM `call` jobs through the outbox, on the guard's `ua_registry` rule.
struct EvmLane {
    state: Arc<Mutex<FakeOdoo>>,
    sub: AsyncMutex<Submitter>,
}

impl EvmLane {
    async fn start(e: &Evm) -> EvmLane {
        let state = Arc::new(Mutex::new(FakeOdoo::default()));
        let odoo = odoo_at(start_fake(state.clone()).await);
        let cfg = ChainCfg {
            family: "evm".into(),
            evm_chain_number: e.id,
            rpc_urls: vec![e.rpc.clone()],
            lanes: vec![0],
            finality: FinalityCfg { mode: "depth".into(), depth: 0, quorum: 1 },
            poll_ms: 200,
            stuck_after_secs: 60,
            max_gas_per_tx: 60_000_000,
            max_fee_cap_gwei: 500,
            ua_registry: Some(e.registry),
            ..Default::default()
        };
        let lane: PrivateKeySigner = LANE_KEY.parse().unwrap();
        let sub = Submitter::start(Chain::with_signer(&cfg, lane).unwrap(), odoo, cfg, "ua8-b".into(), Default::default()).await.unwrap();
        EvmLane { state, sub: AsyncMutex::new(sub) }
    }

    /// One `call` job on the registry, expecting `mined`, its gas logged.
    async fn mined(&self, e: &Evm, what: &str, data: Vec<u8>) {
        let id = JOB.fetch_add(1, Ordering::Relaxed);
        let target = format!("{:#x}", e.registry);
        self.state.lock().unwrap().jobs.push(json!({"id": id, "kind": "call", "call": {"target": target, "calldata": h(&data), "validUntil": (now() + 600).to_string()}}));
        let mut s = self.sub.lock().await;
        s.poll_outbox().await;
        for _ in 0..200 {
            s.track().await;
            if s.inflight_count() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let tx = {
            let o = self.state.lock().unwrap();
            assert_eq!(last_state(&o, id), "mined", "{what}: {:?}", o.reports.iter().rev().find(|r| r["job_id"] == id));
            report_of(&o, id, "signed")["tx_hash"].as_str().unwrap().to_string()
        };
        let p = ProviderBuilder::new().connect_http(e.rpc.parse().unwrap());
        let hash: B256 = tx.parse().unwrap();
        println!("COPY evm {} {what}: gas_used {} (call job)", e.id, p.get_transaction_receipt(hash).await.unwrap().unwrap().gas_used);
    }
}

// ---------- signers ----------

/// A seeded `mldsa65` key, signing as `ua-registry`'s tests sign.
struct Ml {
    sk: Box<SigningKey<MlDsa65>>,
    key: Vec<u8>,
    ua: [u8; 32],
}

impl Ml {
    fn new(seed: u8) -> Ml {
        let sk = Box::new(SigningKey::<MlDsa65>::from_seed(&Seed::from([seed; 32])));
        let key = sk.verifying_key().encode().as_slice().to_vec();
        Ml { ua: scaas_ua::ua_of(MLDSA65, &key).unwrap(), sk, key }
    }

    fn sign(&self, ua_msg: &[u8; 32]) -> Vec<u8> {
        let m = scaas_ua::pq::signed_message(MLDSA65, ua_msg);
        self.sk.expanded_key().sign_deterministic(&m, &[]).unwrap().encode().as_slice().to_vec()
    }
}

/// `ua_message(MSIG, purpose, digest)`'s member message under `kind`.
fn member_message(kind: u16, ua: &[u8; 32], purpose: &[u8; 32], digest: &[u8; 32]) -> [u8; 32] {
    let md = scaas_ua::member_digest(ua, &scaas_ua::ua_message(MSIG, purpose, digest).unwrap());
    scaas_ua::ua_message(kind, &scaas_ua::purpose_tag("member").unwrap(), &md).unwrap()
}

fn no_attrs() -> UAAttrs {
    UAAttrs::default()
}

/// What a `register` of `(kind, ua)` signs for `attrs`.
fn register_digest(kind: u16, ua: &[u8; 32], attrs: &UAAttrs, pqz_key_hash: &[u8; 32]) -> [u8; 32] {
    let pk = attrs.kem.kem_pk();
    let pk = if attrs.kem.scheme == 0 { &[][..] } else { &pk };
    ua8::registration_digest(ua, kind, pqz_key_hash, &ua8::kem_record_hash(ua, 0, pk).unwrap(), &attrs.pqz_pop_hash)
}

/// The PQZ key, proof, proof hash and `register` KEM key of a set, from `mldsa65/<set>`.
fn set_attrs(set: &str) -> (UAAttrs, Vec<u8>, [u8; 32]) {
    let r = row("registrations", &format!("mldsa65/{set}"));
    (Rec::of_row(&r).attrs, hx(&r["pqzPop"]), hx32(&r["pqzKeyHash"]))
}

/// A single `mldsa65` registration with `attrs`.
fn ml_rec(m: &Ml, attrs: &UAAttrs, pqz_key_hash: &[u8; 32], pqz_pop: Vec<u8>) -> Rec {
    let d = register_digest(MLDSA65, &m.ua, attrs, pqz_key_hash);
    let pop = m.sign(&scaas_ua::ua_message(MLDSA65, &ua8::pop_v2_tag(), &d).unwrap());
    Rec { kind: MLDSA65, key_data: m.key.clone(), attrs: attrs.clone(), pop, pqz_pop }
}

/// An `msig` of `mldsa65` keys with weights, its key data in id order.
struct Ms<'a> {
    members: Vec<(&'a Ml, u16)>,
    key_data: Vec<u8>,
    ua: [u8; 32],
}

impl<'a> Ms<'a> {
    fn new(threshold: u16, mut members: Vec<(&'a Ml, u16)>) -> Ms<'a> {
        members.sort_by_key(|m| m.0.ua);
        let list: Vec<_> = members.iter().map(|(m, w)| (MLDSA65, m.ua, *w)).collect();
        let key_data = scaas_ua::encode_msig(threshold, &list);
        Ms { ua: scaas_ua::ua_of(MSIG, &key_data).unwrap(), key_data, members }
    }

    /// The slots of `signers` (member indexes) over `(purpose, digest)`.
    fn slots(&self, signers: &[usize], purpose: &[u8; 32], digest: &[u8; 32]) -> Vec<MemberSig> {
        signers.iter().map(|&i| MemberSig { index: i as u16, key_data: vec![], sig: self.members[i].0.sign(&member_message(MLDSA65, &self.ua, purpose, digest)) }).collect()
    }

    fn rec(&self, signers: &[usize], attrs: &UAAttrs, pqz_key_hash: &[u8; 32], pqz_pop: Vec<u8>) -> Rec {
        let d = register_digest(MSIG, &self.ua, attrs, pqz_key_hash);
        let pop = encode_member_sigs(&self.slots(signers, &ua8::pop_v2_tag(), &d));
        Rec { kind: MSIG, key_data: self.key_data.clone(), attrs: attrs.clone(), pop, pqz_pop }
    }

    fn every(&self) -> Vec<usize> {
        (0..self.members.len()).collect()
    }
}

/// `set_kem_key(ua, version, kem, slots)` of an `msig`, or a single key's `signature`, as the job's arguments.
fn set_kem_args(ua: &[u8; 32], version: u64, kem: &KemKey, sig: Value) -> Value {
    json!({"ua": h(ua), "version": version, "kem": kem_json(kem), "sig": sig, "relayer": null})
}

fn msig_sig(slots: &[MemberSig]) -> Value {
    json!({"key_data": "0x", "signature": "0x", "members": member_sigs_json(slots)})
}

// ---------- the copy ----------

struct Copy {
    a: Evm,
    b: Evm,
    lane_b: EvmLane,
    s: Node,
}

static COPY: OnceCell<Copy> = OnceCell::const_new();

async fn copy_stack() -> &'static Copy {
    COPY.get_or_init(|| async {
        let (a, b) = (Evm::up("UA8_EVM_A").await, Evm::up("UA8_EVM_B").await);
        assert_ne!(a.id, b.id);
        let lane_b = EvmLane::start(&b).await;
        Copy { a, b, lane_b, s: fresh_node().await }
    }).await
}

/// `row` registered on A by its own client, read there, relayed to Soroban from that read, read there, relayed to B from that
/// read, read there: every read byte-equal to the source it was copied from, and A's to the vector.
async fn copy_registration(c: &Copy, name: &str, relayer: &Value) -> Rec {
    let vector = Rec::of_row(&row("registrations", name));
    let ua = vector.ua();
    // EVM verifies ML-DSA on the key's expanded cache (P6c): anyone's two transactions on each chain, no part of the record
    if vector.kind == MLDSA65 {
        c.a.cache_key(name, &vector.key_data).await;
        c.b.cache_key(name, &vector.key_data).await;
    }
    c.a.send(&format!("register {name}"), vector.calldata()).await;
    if !vector.pqz_pop.is_empty() {
        c.a.send(&format!("storePqzPop {name}"), storePqzPopCall { ua: ua.into(), pqzPop: vector.pqz_pop.clone().into() }.abi_encode()).await;
    }
    let on_a = c.a.rec(&ua).await;
    on_a.eq(&format!("{name}: EVM A against the vector"), &vector);

    let (f, args) = on_a.job_args(relayer);
    c.s.mined(&format!("copy {f} {name}"), f, args).await;
    let on_s = c.s.rec(&ua).await;
    on_s.eq(&format!("{name}: Soroban against EVM A"), &on_a);

    c.lane_b.mined(&c.b, &format!("register {name}"), on_s.calldata()).await;
    if !on_s.pqz_pop.is_empty() {
        c.lane_b.mined(&c.b, &format!("storePqzPop {name}"), storePqzPopCall { ua: ua.into(), pqzPop: on_s.pqz_pop.clone().into() }.abi_encode()).await;
    }
    let on_b = c.b.rec(&ua).await;
    on_b.eq(&format!("{name}: EVM B against Soroban"), &on_s);
    on_b.eq(&format!("{name}: EVM B against the vector"), &vector);
    println!("COPY {name}: register byte-equal on A, Soroban and B: key_data {} B, pop {} B, pqz_key {} B, pqz_pop {} B, kem_ek {} B",
             on_b.key_data.len(), on_b.pop.len(), on_b.attrs.pqz_key.len(), on_b.pqz_pop.len(), on_b.attrs.kem.mlkem_ek.len());
    on_b
}

/// `checked_of` against `ua8-roundtrip.json`: the same code on the real host as on the unit host.
async fn check_marks(c: &Copy, name: &str, ua: &[u8; 32]) {
    let want = round_trip(name);
    let got = c.s.checked_of(ua).await;
    assert_eq!([got[0].0, got[1].0, got[2].0], ["pop", "pqzPop", "kem"].map(|k| want["checked"][k].as_u64().unwrap()), "{name}: checked_of");
    println!("COPY {name}: checked_of {got:?}");
}

/// The KEM records of `name` in the vector's order, each from the row to A, from A's read to Soroban, from Soroban's read to B.
/// `kem_key_of` after each write must be `ua8-roundtrip.json`'s, on each chain: a later, lower version never lowers it.
async fn copy_kem(c: &Copy, name: &str, rec: &Rec, relayer: &Value) {
    let (ua, want) = (rec.ua(), round_trip(name));
    let (order, max_after) = (want["kemOrder"].as_array().unwrap(), want["kemMaxAfter"].as_array().unwrap());
    assert!(!order.is_empty(), "{name} has KEM records");
    for (v, max) in order.iter().zip(max_after) {
        let (v, max) = (v.as_u64().unwrap(), max.as_u64().unwrap());
        let rows = portable()["kemRecords"].as_array().unwrap().clone();
        let r = rows.iter().find(|k| hx(&k["ua"]) == ua && k["version"] == v).unwrap();
        let (vk, vsig) = (KemKey::from_kem_pk(&hx(&r["kemPk"])).unwrap(), hx(&r["sig"]));
        c.a.send(&format!("setKemKey {name} v{v}"), setKemKeyCall { ua: ua.into(), version: v, kem: sol_kem(&vk), sig: sol_sig(rec.kind, &vsig) }.abi_encode()).await;
        let (ak, asig) = c.a.kem_at(&ua, v).await;
        kem_eq(&format!("{name} v{v}: EVM A against the vector"), &ak, &vk);
        same(&format!("{name} v{v}: EVM A against the vector"), "sig", &asig, &vsig);

        c.s.mined(&format!("copy set_kem_key {name} v{v}"), "set_kem_key",
                  json!({"ua": h(&ua), "version": v, "kem": kem_json(&ak), "sig": sig_json(rec.kind, &asig), "relayer": relayer})).await;
        let (sk, ssig, _) = c.s.kem_at(&ua, v).await;
        kem_eq(&format!("{name} v{v}: Soroban against EVM A"), &sk, &ak);
        same(&format!("{name} v{v}: Soroban against EVM A"), "sig", &ssig, &asig);

        c.lane_b.mined(&c.b, &format!("setKemKey {name} v{v}"), setKemKeyCall { ua: ua.into(), version: v, kem: sol_kem(&sk), sig: sol_sig(rec.kind, &ssig) }.abi_encode()).await;
        let (bk, bsig) = c.b.kem_at(&ua, v).await;
        kem_eq(&format!("{name} v{v}: EVM B against Soroban"), &bk, &sk);
        same(&format!("{name} v{v}: EVM B against Soroban"), "sig", &bsig, &ssig);

        assert_eq!([c.a.kem_max(&ua).await, c.s.kem_max(&ua).await, c.b.kem_max(&ua).await], [max; 3], "{name}: the highest version after v{v}");
        println!("COPY {name} KEM v{v}: byte-equal on A, Soroban and B, highest version {max}");
    }
}

/// `set_pqz_key`, then `store_pqz_pop`, the same way; `registration_of` does not change: the key is no `register` argument.
async fn copy_pqz(c: &Copy, name: &str, record: &str, rec: &Rec, proof: Vec<u8>, want: (u64, Option<String>), relayer: &Value) {
    let (ua, r) = (rec.ua(), row("pqzKeyRecords", record));
    let (vkey, vhash, vsig) = (hx(&r["pqzKey"]), hx32(&r["pqzPopHash"]), hx(&r["sig"]));
    assert_eq!(scaas_ua::keccak256(&proof), vhash, "the proof of the record's hash");
    c.a.send(&format!("setPqzKey {record}"), setPqzKeyCall { ua: ua.into(), pqzKey: vkey.clone().into(), pqzPopHash: vhash.into(), sig: sol_sig(rec.kind, &vsig) }.abi_encode()).await;
    let (akey, ahash, asig) = c.a.pqz(&ua).await;
    let w = format!("{record}: EVM A against the vector");
    same(&w, "key", &akey, &vkey);
    same(&w, "pqz_pop_hash", &ahash, &vhash);
    same(&w, "sig", &asig, &vsig);

    c.s.mined(&format!("copy set_pqz_key {record}"), "set_pqz_key",
              json!({"ua": h(&ua), "pqz_key": h(&akey), "pqz_pop_hash": h(&ahash), "sig": sig_json(rec.kind, &asig), "relayer": relayer})).await;
    let v = read(&c.s.registry, "pqz_key_of", vec![sc_bytes(&ua)]).await;
    let t = tuple(&v);
    let (skey, shash, proven, mark) = (by(&t[0]), by32(&t[1]), &t[2], checked(&t[3]));
    assert_eq!(proven, &ScVal::Bool(false), "nothing proves a PQZ key on Soroban (U8S-D6)");
    assert_eq!(mark, want, "{record}: who checked it");
    let ssig = by(&read(&c.s.registry, "pqz_key_sig_of", vec![sc_bytes(&ua)]).await);
    let w = format!("{record}: Soroban against EVM A");
    same(&w, "key", &skey, &akey);
    same(&w, "pqz_pop_hash", &shash, &ahash);
    same(&w, "sig", &ssig, &asig);

    c.lane_b.mined(&c.b, &format!("setPqzKey {record}"), setPqzKeyCall { ua: ua.into(), pqzKey: skey.clone().into(), pqzPopHash: shash.into(), sig: sol_sig(rec.kind, &ssig) }.abi_encode()).await;
    let (bkey, bhash, bsig) = c.b.pqz(&ua).await;
    let w = format!("{record}: EVM B against Soroban");
    same(&w, "key", &bkey, &skey);
    same(&w, "pqz_pop_hash", &bhash, &shash);
    same(&w, "sig", &bsig, &ssig);

    c.a.send(&format!("storePqzPop {record}"), storePqzPopCall { ua: ua.into(), pqzPop: proof.clone().into() }.abi_encode()).await;
    let apop = c.a.pqz_pop(&ua).await;
    same(&format!("{record}: EVM A against the proof"), "pqz_pop", &apop, &proof);
    c.s.mined(&format!("copy store_pqz_pop {record}"), "store_pqz_pop", json!({"ua": h(&ua), "pqz_pop": h(&apop)})).await;
    let spop = by(&read(&c.s.registry, "pqz_pop_of", vec![sc_bytes(&ua)]).await);
    same(&format!("{record}: Soroban against EVM A"), "pqz_pop", &spop, &apop);
    c.lane_b.mined(&c.b, &format!("storePqzPop {record}"), storePqzPopCall { ua: ua.into(), pqzPop: spop.clone().into() }.abi_encode()).await;
    let bpop = c.b.pqz_pop(&ua).await;
    same(&format!("{record}: EVM B against Soroban"), "pqz_pop", &bpop, &spop);

    c.a.rec(&ua).await.eq(&format!("{name}: EVM A after setPqzKey"), rec);
    c.s.rec(&ua).await.eq(&format!("{name}: Soroban after set_pqz_key"), rec);
    c.b.rec(&ua).await.eq(&format!("{name}: EVM B after setPqzKey"), rec);
    println!("COPY {record}: set_pqz_key + store_pqz_pop byte-equal on A, Soroban and B: key {} B, proof {} B, sig {} B", bkey.len(), bpop.len(), bsig.len());
}

#[tokio::test]
#[ignore]
async fn e2e_ua8_copy_evm_soroban_evm() {
    let c = copy_stack().await;
    let (lane, none) = (json!(g(&key(0))), Value::Null);
    // `fndsa512`: chain-verified on both EVM chains, relayer-checked here (S3, U8S-D8), KEM records 3 then 1
    let f = copy_registration(c, "fndsa512", &lane).await;
    copy_kem(c, "fndsa512", &f, &lane).await;
    check_marks(c, "fndsa512", &f.ua()).await;
    let proof = hx(&row("registrations", "mldsa65/n2816-kmax65536")["pqzPop"]);
    copy_pqz(c, "fndsa512", "fndsa512/n2816-kmax65536", &f, proof.clone(), (2, Some(g(&key(0)))), &lane).await;

    // `mldsa65` at the largest set, `Chain` here: PQZ key, proof and KEM key given at `register`, KEM records 3, 1, 2
    let name = "mldsa65/n2816-kmax65536";
    let m = copy_registration(c, name, &none).await;
    copy_kem(c, name, &m, &none).await;
    check_marks(c, name, &m.ua()).await;
    let v = read(&c.s.registry, "pqz_key_of", vec![sc_bytes(&m.ua())]).await;
    same(name, "pqz_key_of", &by(&tuple(&v)[0]), &m.attrs.pqz_key);

    // an `msig` with its minimal `pop`, a native slot beside an `mldsa65` slot; then its PQZ key signed by both
    copy_registration(c, "mldsa65#1", &none).await;
    let name = "msig-pq-native";
    let m = copy_registration(c, name, &none).await;
    check_marks(c, name, &m.ua()).await;
    copy_pqz(c, name, "msig-pq-native/n2816-kmax65536", &m, proof, (1, None), &none).await;

    // `msig-pq` (two `mldsa65` members) goes through the unit round trip only: without the ML-DSA precompile EVM's verify
    // budget refuses it, so this direction of a copy does not exist on such a chain
    let (m1, m2) = ("mldsa65#2", "msig-pq/n2816-kmax65536");
    copy_registration(c, m1, &none).await;
    let r = Rec::of_row(&row("registrations", m2));
    let p = ProviderBuilder::new().connect_http(c.a.rpc.parse().unwrap());
    let e = p.call(TransactionRequest::default().to(c.a.registry).input(r.calldata().into())).await.unwrap_err().to_string();
    println!("COPY {m2} on EVM without the ML-DSA precompile: refused, {}", e.chars().take(120).collect::<String>());
    assert!(e.contains("0xe9472176"), "UAKeyData(0x0120): {e}");
}

// ---------- P1, P2: what the RPC and the chain do with the node's auth entry ----------

/// P1: an `msig` whose `pop` has a slot of the `G…` account `signer`, and a real ML-DSA-65 slot.
async fn g_member_job(n: &Node, ml: &Ml, signer: u32, relayer: &Value) -> Value {
    let s = key(signer).public_key();
    let id: [u8; 32] = s.try_into().unwrap();
    let mut list = vec![(STELLAR_ACCOUNT, id, 1u16), (MLDSA65, ml.ua, 1)];
    list.sort_by_key(|m| m.1);
    let kd = scaas_ua::encode_msig(2, &list);
    let ua = scaas_ua::ua_of(MSIG, &kd).unwrap();
    let d = register_digest(MSIG, &ua, &no_attrs(), &[0; 32]);
    let slots: Vec<MemberSig> = list.iter().enumerate().map(|(i, m)| MemberSig {
        index: i as u16, key_data: vec![],
        sig: if m.0 == MLDSA65 { ml.sign(&member_message(MLDSA65, &ua, &ua8::pop_v2_tag(), &d)) } else { vec![] },
    }).collect();
    let rec = Rec { kind: MSIG, key_data: kd, attrs: no_attrs(), pop: encode_member_sigs(&slots), pqz_pop: vec![] };
    let (f, args) = rec.job_args(relayer);
    call_job(&n.registry, f, args)
}

fn sim_answer(sim: &Value) -> String {
    let auth = sim["results"][0]["auth"].as_array();
    format!("error {:?}, results[0].auth {:?} entries", sim.get("error").and_then(|e| e.as_str()).map(|e| e.chars().take(160).collect::<String>()), auth.map(|a| a.len()))
}

/// P1: with an entry in the transaction the RPC enforces; without one it records. So for `Some(lane)` the node's two guards see
/// only what the host let pass, which is the entry the node built: the refusal is the host's, at simulation, and the guards
/// cannot fire. With `None` they read a real recording, and they do fire.
#[tokio::test]
#[ignore]
async fn e2e_ua8_simulation_auth_mode() {
    let n = fresh_node().await;
    let (registry, lane) = (sc(&n.registry), sc(&g(&key(0))));
    let ml = Ml::new(0x31);
    let (f, args) = ml_rec(&ml, &no_attrs(), &[0; 32], vec![]).job_args(&Value::Null);
    n.mined("P1 register the ML-DSA member", f, args).await;
    let (me, none) = (json!(g(&key(0))), Value::Null);

    // a part the host asks of nobody: what comes back for an entry nothing uses, and for none
    let op_of = |job: &Value| job["op"].clone();
    let j = g_member_job(&n, &ml, BYSTANDER, &me).await;
    let (call, auth) = ua8_call_job(&op_of(&j), &lane, &registry, true).unwrap();
    assert_eq!(auth.len(), 1);
    let enforced = simulate(0, call.clone(), auth.clone()).await;
    println!("P1 auth = [lane entry], G member's slot, default mode: {}", sim_answer(&enforced));
    let explicit = simulate_rpc(0, call.clone(), auth.clone(), json!({"authMode": "record"})).await;
    println!("P1 auth = [lane entry], authMode record: {}", explicit.get("error").map_or(sim_answer(&explicit["result"]), |e| e.to_string()));
    let recorded = simulate(0, call.clone(), vec![]).await;
    println!("P1 auth = [], the same call, default mode: {}", sim_answer(&recorded));
    let enforcing = enforced.get("error").is_some_and(|e| e.as_str().unwrap_or_default().contains("Error(Auth,"));
    let records = recorded.get("error").is_none() && recorded["results"][0]["auth"].as_array().is_some_and(|a| !a.is_empty());
    println!("P1 result: a non-empty auth {} (Some(lane)), an empty auth {}", if enforcing { "ENFORCES" } else { "RECORDS" }, if records { "RECORDS" } else { "ENFORCES" });
    assert!(enforcing && records, "simulation mode changed: read the guards again");

    // a write that succeeds with the lane's entry: the entries the guards then read
    let row_f = Rec::of_row(&row("registrations", "fndsa512"));
    let (f, args) = row_f.job_args(&me);
    let j = call_job(&n.registry, f, args);
    let (call, auth) = ua8_call_job(&j["op"], &lane, &registry, true).unwrap();
    let ok = simulate(0, call, auth.clone()).await;
    let back = ok["results"][0]["auth"].as_array().cloned().unwrap_or_default();
    let same_entry = back.iter().all(|x| SorobanAuthorizationEntry::from_xdr_base64(x.as_str().unwrap(), Limits::none()).unwrap() == auth[0]);
    println!("P1 enforcing simulation that passes: {}, every entry returned is the node's own: {same_entry}", sim_answer(&ok));
    assert!(!back.is_empty() && same_entry, "an enforcing simulation answers the node's entry and nothing else");

    // the node end to end. `Some(lane)`: the host refuses; `None`: the guards refuse
    let refused = |what: &str, r: (String, Value, Option<String>)| {
        println!("P1 node, {what}: job {}, reason {}", r.0, r.1["error"]);
        assert_eq!(r.0, "dead", "{what}");
        assert!(r.2.is_none(), "{what}: never signed");
        r.1["error"].as_str().unwrap_or_default().to_string()
    };
    let e = refused("relayer = Some(lane), G slot of another account", n.run(0, g_member_job(&n, &ml, BYSTANDER, &me).await).await);
    assert!(e.contains("Error(Auth,"), "the host's refusal: {e}");
    let e = refused("relayer = None, G slot of another account", n.run(0, g_member_job(&n, &ml, BYSTANDER, &none).await).await);
    assert!(e.contains("needs another account's signature"), "check_no_other_signer: {e}");
    let e = refused("relayer = Some(lane), G slot of this lane", n.run(0, g_member_job(&n, &ml, 0, &me).await).await);
    assert!(e.contains("Error(Auth,"), "the host's refusal: {e}");
    let e = refused("relayer = None, G slot of this lane", n.run(0, g_member_job(&n, &ml, 0, &none).await).await);
    assert!(e.contains("lane's authority"), "check_recorded_auth: {e}");
}

/// P2: `relayer = Some(lane)` on a part the chain verifies: the contract never reads the entry the node adds.
#[tokio::test]
#[ignore]
async fn e2e_ua8_unused_source_account_entry() {
    let n = fresh_node().await;
    let ml = Ml::new(0x32);
    let lane = g(&key(0));
    let rec = ml_rec(&ml, &no_attrs(), &[0; 32], vec![]);
    let (f, args) = rec.job_args(&json!(lane));
    let (state, last, tx) = n.run(0, call_job(&n.registry, f, args)).await;
    println!("P2 Chain part, relayer = Some(lane): job {state}, {last}");
    assert_eq!(state, "mined", "{last}");
    let tx = tx.unwrap();
    fit("P2 register mldsa65, relayer = Some(lane), entry unused", &tx).await;
    let r = await_tx(&tx).await;
    let env = TransactionEnvelope::from_xdr_base64(r["envelopeXdr"].as_str().unwrap(), Limits::none()).unwrap();
    let (_, o) = landed_op(&env);
    assert_eq!(o.auth.len(), 1, "the unused entry was in the transaction");
    assert_eq!(n.checked_of(&rec.ua()).await[0].0, 1, "a part the chain verified stays Chain: the lane's entry marked nothing");
    n.rec(&rec.ua()).await.eq("P2: Soroban against the arguments", &rec);
    println!("P2 result: ACCEPTED on chain, status {}, {} auth entry in the envelope, unused, pop_checked Chain", r["status"], o.auth.len());
}

// ---------- P4: the network fit ----------

async fn network_limits() {
    let s = cli(&["network", "settings", "--output", "json"]);
    let v: Value = serde_json::from_str(&s).unwrap();
    let find = |k: &str| {
        fn walk(v: &Value, k: &str) -> Option<Value> {
            match v {
                Value::Object(m) => m.get(k).cloned().or_else(|| m.values().find_map(|x| walk(x, k))),
                Value::Array(a) => a.iter().find_map(|x| walk(x, k)),
                _ => None,
            }
        }
        walk(&v, k).unwrap_or(Value::Null)
    };
    println!("LIMITS tx_max_instructions {} tx_memory_limit {} tx_max_disk_read_bytes {} tx_max_write_bytes {} tx_max_footprint_entries {} tx_max_write_ledger_entries {} tx_max_size_bytes {} contract_data_entry_size_bytes {} tx_max_contract_events_size_bytes {}",
             find("tx_max_instructions"), find("tx_memory_limit"), find("tx_max_disk_read_bytes"), find("tx_max_write_bytes"), find("tx_max_footprint_entries"),
             find("tx_max_write_ledger_entries"), find("tx_max_size_bytes"), find("contract_data_entry_size_bytes"), find("tx_max_contract_events_size_bytes"));
}

/// One job, mined or refused: a data row, not a gate.
async fn data_row(n: &Node, what: &str, f: &str, args: Value) -> bool {
    let (state, last, tx) = n.run(0, call_job(&n.registry, f, args)).await;
    if state == "mined" {
        fit(what, &tx.unwrap()).await;
        return true;
    }
    println!("FIT {what}: REFUSED, job {state}: {}", last["error"]);
    false
}

/// `relayer = None` `set_pqz_key` arguments signed by `slots`.
fn pqz_args(ua: &[u8; 32], a: &UAAttrs, sig: Value) -> Value {
    json!({"ua": h(ua), "pqz_key": h(&a.pqz_key), "pqz_pop_hash": h(&a.pqz_pop_hash), "sig": sig, "relayer": null})
}

/// C12, the brief's item 4: a real `set_kem_key` / `set_pqz_key`, which load the whole `Ua(ua)`, and the largest `register` per
/// set, as transactions that land; the published limits at the edge, one over each. A single-key `mldsa65` over a limit after
/// the split is a STOP (C12); everything `data_row` runs is published data.
#[tokio::test]
#[ignore]
async fn e2e_ua8_network_fit() {
    network_limits().await;
    let n = fresh_node().await;
    let none = Value::Null;
    let (pk, pqz_tag) = (scaas_ua::purpose_tag("kem").unwrap(), scaas_ua::purpose_tag("pqz-key").unwrap());
    let kem1 = KemKey::from_kem_pk(&hx(&row("kemRecords", "mldsa65/v1")["kemPk"])).unwrap();
    let pool: Vec<Ml> = (0..24).map(|i| Ml::new(0x40 + i)).collect();
    for (i, m) in pool.iter().enumerate() {
        let (f, args) = ml_rec(m, &no_attrs(), &[0; 32], vec![]).job_args(&none);
        let (state, last, _) = n.run(0, call_job(&n.registry, f, args)).await;
        assert_eq!(state, "mined", "member {i}: {last}");
    }

    for (si, set) in SETS.iter().enumerate() {
        let (attrs, proof, pqz_hash) = set_attrs(set);
        let split = |r: &Rec| Rec { pqz_pop: vec![], ..r.clone() };
        // single-key mldsa65, the gate: full, split + store_pqz_pop, set_kem_key, set_pqz_key
        let (a, b, c) = (Ml::new(0x80 + 3 * si as u8), Ml::new(0x81 + 3 * si as u8), Ml::new(0x82 + 3 * si as u8));
        let full = ml_rec(&a, &attrs, &pqz_hash, proof.clone());
        let (f, args) = full.job_args(&none);
        n.mined(&format!("register mldsa65 {set} full"), f, args).await;
        n.rec(&a.ua).await.eq(&format!("mldsa65 {set} full, read back"), &full);
        let parted = ml_rec(&b, &attrs, &pqz_hash, proof.clone());
        let (f, args) = split(&parted).job_args(&none);
        n.mined(&format!("GATE register mldsa65 {set} split"), f, args).await;
        n.mined(&format!("GATE store_pqz_pop mldsa65 {set}"), "store_pqz_pop", json!({"ua": h(&b.ua), "pqz_pop": h(&proof)})).await;
        n.rec(&b.ua).await.eq(&format!("mldsa65 {set} split, read back"), &parted);
        let d = ua8::kem_record_digest(&a.ua, 1, &kem1.kem_pk()).unwrap();
        let sig = a.sign(&scaas_ua::ua_message(MLDSA65, &pk, &d).unwrap());
        n.mined(&format!("GATE set_kem_key mldsa65 {set}"), "set_kem_key", set_kem_args(&a.ua, 1, &kem1, json!({"key_data": "0x", "signature": h(&sig), "members": []}))).await;
        let (f, args) = ml_rec(&c, &no_attrs(), &[0; 32], vec![]).job_args(&none);
        n.mined(&format!("register mldsa65 {set} no attributes"), f, args).await;
        let d = ua8::pqz_key_record_digest(&c.ua, &pqz_hash, &attrs.pqz_pop_hash);
        let sig = c.sign(&scaas_ua::ua_message(MLDSA65, &pqz_tag, &d).unwrap());
        n.mined(&format!("GATE set_pqz_key mldsa65 {set}"), "set_pqz_key", pqz_args(&c.ua, &attrs, json!({"key_data": "0x", "signature": h(&sig), "members": []}))).await;
        let v = read(&n.registry, "pqz_key_of", vec![sc_bytes(&c.ua)]).await;
        same(&format!("set_pqz_key mldsa65 {set}"), "key", &by(&tuple(&v)[0]), &attrs.pqz_key);

        // the largest `register`: 16 of 16 with PQZ + KEM, whole and split; the same record's set_kem_key, 16 slots, which
        // loads the whole `Ua(ua)`
        let group = |k: usize, len: usize, t: u16| Ms::new(t, pool[k..k + len].iter().map(|m| (m, 1)).collect());
        let (m16, n16) = (group(2 * si, 16, 16), group(2 * si + 1, 16, 16));
        let whole = m16.rec(&m16.every(), &attrs, &pqz_hash, proof.clone());
        let (f, args) = whole.job_args(&none);
        if data_row(&n, &format!("register_msig n=16 {set} full"), f, args).await {
            n.rec(&m16.ua).await.eq(&format!("msig n=16 {set} full, read back"), &whole);
        }
        let parted = n16.rec(&n16.every(), &attrs, &pqz_hash, proof.clone());
        let (f, args) = split(&parted).job_args(&none);
        n.mined(&format!("register_msig n=16 {set} split"), f, args).await;
        n.mined(&format!("store_pqz_pop msig n=16 {set}"), "store_pqz_pop", json!({"ua": h(&n16.ua), "pqz_pop": h(&proof)})).await;
        n.rec(&n16.ua).await.eq(&format!("msig n=16 {set} split, read back"), &parted);
        let d = ua8::kem_record_digest(&n16.ua, 1, &kem1.kem_pk()).unwrap();
        n.mined(&format!("set_kem_key msig n=16 {set}, Ua(ua) loaded"), "set_kem_key", set_kem_args(&n16.ua, 1, &kem1, msig_sig(&n16.slots(&n16.every(), &pk, &d)))).await;

        // the largest `Ua(ua)` a `set_pqz_key` can load: 15 light slots at `register`, one heavy member later (a minimal
        // 16-slot `pop` needs all 16 again, over the entry limit: U8S-D1)
        let mut w: Vec<(&Ml, u16)> = pool[si..si + 15].iter().map(|m| (m, 1)).collect();
        w.push((&pool[si + 15], 15));
        let heavy = Ms::new(15, w);
        let at = heavy.members.iter().position(|m| m.1 == 15).unwrap();
        let light: Vec<usize> = heavy.every().into_iter().filter(|i| *i != at).collect();
        let (f, args) = heavy.rec(&light, &no_attrs(), &[0; 32], vec![]).job_args(&none);
        n.mined(&format!("register_msig 15 slots {set}"), f, args).await;
        let d = ua8::pqz_key_record_digest(&heavy.ua, &pqz_hash, &attrs.pqz_pop_hash);
        n.mined(&format!("set_pqz_key msig Ua(ua) of 15 slots {set}, 1 slot"), "set_pqz_key", pqz_args(&heavy.ua, &attrs, msig_sig(&heavy.slots(&[at], &pqz_tag, &d)))).await;

        // the published edge: 13 / 13 / 12 / 12 ML-DSA-65 slots fit, one more does not
        let limit = [13, 13, 12, 12][si];
        let at_edge = group(si, limit, limit as u16);
        let (f, args) = at_edge.rec(&at_edge.every(), &no_attrs(), &[0; 32], vec![]).job_args(&none);
        n.mined(&format!("register_msig {limit} slots {set}"), f, args).await;
        let d = ua8::pqz_key_record_digest(&at_edge.ua, &pqz_hash, &attrs.pqz_pop_hash);
        n.mined(&format!("EDGE set_pqz_key {limit} slots {set}"), "set_pqz_key", pqz_args(&at_edge.ua, &attrs, msig_sig(&at_edge.slots(&at_edge.every(), &pqz_tag, &d)))).await;
        let v = read(&n.registry, "pqz_key_sig_of", vec![sc_bytes(&at_edge.ua)]).await;
        println!("EDGE {set}: {limit} slots fit, sig {} B stored", by(&v).len());
        let over = group(si + 4, limit + 1, limit as u16 + 1);
        let (f, args) = over.rec(&over.every(), &no_attrs(), &[0; 32], vec![]).job_args(&none);
        n.mined(&format!("register_msig {} slots {set}", limit + 1), f, args).await;
        let d = ua8::pqz_key_record_digest(&over.ua, &pqz_hash, &attrs.pqz_pop_hash);
        let (state, last, tx) = n.run(0, call_job(&n.registry, "set_pqz_key", pqz_args(&over.ua, &attrs, msig_sig(&over.slots(&over.every(), &pqz_tag, &d))))).await;
        println!("EDGE {set}: {} slots: job {state}, signed {}, reason {}", limit + 1, tx.is_some(), last["error"]);
        assert_ne!(state, "mined", "the published limit moved");
        assert_eq!(read(&n.registry, "pqz_key_of", vec![sc_bytes(&over.ua)]).await, ScVal::Void, "nothing stored");
    }

    // `slhdsa128s` slots: `raw_send`, the chain stores them unread and the off-chain check would refuse the junk signature
    let (registry, lane) = (sc(&n.registry), sc(&g(&key(0))));
    let me = json!(g(&key(0)));
    let sig = vec![0x5a; 7_856];
    let mut members = vec![];
    for i in 0..8u8 {
        let kd = vec![0x80 + i; 32];
        let rec = Rec { kind: SLHDSA128S, key_data: kd.clone(), attrs: no_attrs(), pop: sig.clone(), pqz_pop: vec![] };
        let (f, args) = rec.job_args(&me);
        let (call, auth) = ua8_call_job(&call_job(&n.registry, f, args)["op"], &lane, &registry, true).unwrap();
        n.raw_send(&format!("register slhdsa128s #{i}"), 0, call, auth).await.unwrap();
        members.push((SLHDSA128S, rec.ua(), 1u16));
    }
    members.sort_by_key(|m| m.1);
    let msig_of = |k: usize, c: usize| {
        let kd = scaas_ua::encode_msig(c as u16, &members[k..k + c]);
        let slots: Vec<MemberSig> = (0..c as u16).map(|index| MemberSig { index, key_data: vec![], sig: sig.clone() }).collect();
        Rec { kind: MSIG, key_data: kd, attrs: no_attrs(), pop: encode_member_sigs(&slots), pqz_pop: vec![] }
    };
    let relayed = |rec: &Rec| {
        let (f, args) = rec.job_args(&me);
        ua8_call_job(&call_job(&n.registry, f, args)["op"], &lane, &registry, true).unwrap()
    };
    for (c, fits) in [(7, true), (8, false)] {
        let (call, auth) = relayed(&msig_of(0, c));
        let r = n.raw_send(&format!("EDGE register_msig {c} slhdsa128s slots"), 0, call, auth).await;
        println!("EDGE register {c} slhdsa128s slots: {r:?}");
        assert_eq!(r.is_ok(), fits, "the published limit of register moved: {r:?}");
    }
    // `set_pqz_key`: the bytes rule, 6 slots at the smallest set and 5 at the largest; `Some(lane)` also carries every argument
    // twice, in the lane's auth entry, which the unit host never saw
    for (k, c, set, fits) in [(1, 6, SETS[0], true), (1, 7, SETS[0], false), (2, 5, SETS[3], true), (2, 6, SETS[3], false)] {
        let (attrs, _, _) = set_attrs(set);
        let rec = msig_of(k, c);
        let (call, auth) = relayed(&rec);
        n.raw_send(&format!("register_msig {c} slhdsa128s slots ({set})"), 0, call, auth).await.unwrap();
        let args = json!({"ua": h(&rec.ua()), "pqz_key": h(&attrs.pqz_key), "pqz_pop_hash": h(&attrs.pqz_pop_hash), "sig": sig_json(MSIG, &rec.pop), "relayer": me});
        let (call, auth) = ua8_call_job(&call_job(&n.registry, "set_pqz_key", args)["op"], &lane, &registry, true).unwrap();
        let r = n.raw_send(&format!("EDGE set_pqz_key {c} slhdsa128s slots {set}"), 0, call, auth).await;
        println!("EDGE set_pqz_key {c} slhdsa128s slots at {set}: {r:?}");
        assert_eq!(r.is_ok(), fits, "the published limit of set_pqz_key moved: {r:?}");
    }
    // data: relayer mode with attributes at `register`, where the doubled arguments meet the transaction size
    let (attrs, proof, _) = set_attrs(SETS[3]);
    for (c, proof) in [(5, vec![]), (6, vec![]), (5, proof.clone())] {
        let rec = Rec { attrs: attrs.clone(), pqz_pop: proof.clone(), ..msig_of(0, c) };
        let (call, auth) = relayed(&rec);
        let r = n.raw_send(&format!("register_msig {c} slhdsa128s slots + PQZ + KEM {}", SETS[3]), 0, call, auth).await;
        println!("EDGE register {c} slhdsa128s slots + PQZ + KEM, proof {} B: {r:?}", proof.len());
    }
    let f = row("registrations", "fndsa512");
    for (p, what) in [(proof, "full"), (vec![], "without the proof")] {
        // the second is the `register` the first leaves undone when refused; a key registered once is `AlreadyRegistered`
        let rec = Rec { kind: FNDSA512, key_data: hx(&f["keyData"]), attrs: attrs.clone(), pop: hx(&f["pop"]), pqz_pop: p };
        let (call, auth) = relayed(&rec);
        let r = n.raw_send(&format!("register fndsa512 + PQZ + KEM {} {what}", SETS[3]), 0, call, auth).await;
        println!("EDGE register fndsa512 + PQZ + KEM {what}: {r:?}");
    }
    // through the node: a job whose transaction passes simulation and is over `tx_max_size_bytes`, here 118 KB of arguments
    // carried twice by naming a relayer on `Chain` parts
    let big = Ms::new(16, pool[8..24].iter().map(|m| (m, 1)).collect());
    let (attrs, proof, pqz_hash) = set_attrs(SETS[3]);
    let (f, args) = big.rec(&big.every(), &attrs, &pqz_hash, proof).job_args(&me);
    let (state, last, tx) = n.run(0, call_job(&n.registry, f, args)).await;
    println!("EDGE node, transaction over tx_max_size_bytes: job {state}, signed {}, reason {}", tx.is_some(), last["error"]);
    assert_eq!((state.as_str(), tx.is_none()), ("dead", true), "refused at build: {last}");
    assert!(last["error"].as_str().unwrap_or_default().contains("tx_max_size_bytes"), "{last}");
}

/// A signed `ua_of` of padded key data, whose envelope `adapter` sends at exactly `target` bytes: the node's size is core's.
async fn sized(n: &Node, target: usize) -> scaas_node::adapter::Signed {
    let mut pad = 64;
    loop {
        let args = vec![ScVal::U32(MLDSA65 as u32), sc_bytes(&vec![7; pad])];
        let call = InvokeContractArgs { contract_address: sc(&n.registry), function_name: sym("ua_of"), args: args.try_into().unwrap() };
        let sim = simulate(0, call.clone(), vec![]).await;
        assert!(sim.get("error").is_none(), "{}", sim["error"]);
        let mut data = SorobanTransactionData::from_xdr_base64(sim["transactionData"].as_str().unwrap(), Limits::none()).unwrap();
        data.resource_fee += data.resource_fee * 15 / 100;
        let t = tx(0, 0, 100 + data.resource_fee as u32, call, vec![], TransactionExt::V1(data));
        let seq = n.adapter.sequence(0).await.unwrap();
        let built = Built { job_id: 0, body: t.to_xdr(Limits::none()).unwrap(), valid_until: 0, meta: json!({}) };
        let signed = n.adapter.sign(built, 0, seq).await.unwrap();
        if signed.raw.len() == target {
            return signed;
        }
        pad = (pad as i64 + target as i64 - signed.raw.len() as i64) as usize;
    }
}

/// The real host's reading of the limit the node compares against, plain and fee-bumped. And the question left to the owner: what
/// simulation knows of a write over the entry limit.
#[tokio::test]
#[ignore]
async fn e2e_ua8_tx_size_limit() {
    let s = fresh_node().await;
    let limit = 132_096;
    // a fee bump wraps the same envelope in 128 B more, which the limit does not count
    for (fee_bump, wrap) in [(false, 0), (true, 128)] {
        let n = Node::with_fee_bump(s.registry.clone(), fee_bump).await;
        let at = sized(&n, limit + wrap).await;
        let sent = n.adapter.submit(&at).await;
        let r = await_tx(&at.tx_id).await;
        println!("EDGE {} B sent, {limit} B counted, fee_bump {fee_bump}: sent {:?}, status {}", at.raw.len(), sent.is_ok(), r["status"]);
        assert!(sent.is_ok() && r["status"] == "SUCCESS", "{sent:?} {r}");
        let over = sized(&n, limit + wrap + 4).await;
        let sent = n.adapter.submit(&over).await;
        println!("EDGE {} B sent, {} B counted, fee_bump {fee_bump}: {sent:?}", over.raw.len(), limit + 4);
        assert!(sent.is_err(), "{limit} + 4 B counted must be refused");
    }

    // over the 65,536 B entry limit: one write, no signature to make, so what simulation answers is all that is measured
    let (lane, registry, me) = (sc(&g(&key(0))), sc(&s.registry), json!(g(&key(0))));
    let proof = vec![7; 70_000];
    let (attrs, _, _) = set_attrs(SETS[0]);
    let f = row("registrations", "fndsa512");
    let attrs = UAAttrs { pqz_pop_hash: scaas_ua::keccak256(&proof), ..attrs };
    let rec = Rec { kind: FNDSA512, key_data: hx(&f["keyData"]), attrs, pop: hx(&f["pop"]), pqz_pop: vec![] };
    let (fun, args) = rec.job_args(&me);
    let (call, auth) = ua8_call_job(&call_job(&s.registry, fun, args)["op"], &lane, &registry, true).unwrap();
    s.raw_send("register fndsa512 for the entry limit", 0, call, auth).await.unwrap();
    let job = call_job(&s.registry, "store_pqz_pop", json!({"ua": h(&rec.ua()), "pqz_pop": h(&proof)}));
    let (call, auth) = ua8_call_job(&job["op"], &lane, &registry, false).unwrap();
    let sim = simulate(0, call, auth).await;
    let data = SorobanTransactionData::from_xdr_base64(sim["transactionData"].as_str().unwrap_or_default(), Limits::none());
    let changes: Vec<usize> = sim["stateChanges"].as_array().into_iter().flatten()
        .filter_map(|c| c["after"].as_str()).map(|x| base64::Engine::decode(&base64::engine::general_purpose::STANDARD, x).unwrap().len()).collect();
    println!("ENTRY simulation of a 70,000 B write: error {:?}, write_bytes {:?}, stateChanges after {changes:?} B, fields {:?}",
             sim.get("error").is_some(), data.as_ref().map(|d| d.resources.write_bytes).ok(), sim.as_object().map(|o| o.keys().cloned().collect::<Vec<_>>()));
    let (state, last, tx) = s.run(0, job).await;
    println!("ENTRY the same job through the node: job {state}, signed {}, reason {}", tx.is_some(), last["error"]);
}

// ---------- P5: a relayer-checked slot, signed, through `check_*` ----------

/// A fresh `fndsa512` key: no vector row has an `msig` slot of a kind the chain cannot verify.
struct Falcon {
    key: Vec<u8>,
    ua: [u8; 32],
    sk: falcon::SecretKey,
}

impl Falcon {
    fn new() -> Falcon {
        let (pk, sk) = falcon::keypair();
        let key = pk.as_bytes().to_vec();
        Falcon { ua: scaas_ua::ua_of(FNDSA512, &key).unwrap(), key, sk }
    }

    fn sign(&self, ua_msg: &[u8; 32]) -> Vec<u8> {
        falcon::detached_sign(ua_msg, &self.sk).as_bytes().to_vec()
    }
}

/// P5: a mixed `msig`, one `fndsa512` slot and one `mldsa65` slot, both signing, end to end: `register` of the `fndsa512` member by
/// its real `pop`, `ua8_precheck` reading the members from the chain and running `check_registration` over the real signature
/// (the group `vk` slice of `signature_ok`, a `slhdsa128s` slot and a BLS slot with `pop = false` have no positive on a host). The same record is also
/// accepted by EVM, which verifies both slots itself, so the node's positive is not its own opinion.
#[tokio::test]
#[ignore]
async fn e2e_ua8_relayer_checked_msig_slot() {
    let c = copy_stack().await;
    // this test's own fake Odoo: the stack's runs on the runtime of the test that made it
    let n = Node::new(c.s.registry.clone()).await;
    let (me, none) = (json!(g(&key(0))), Value::Null);
    let (fk, ml) = (Falcon::new(), Ml::new(0x33));
    let d = register_digest(FNDSA512, &fk.ua, &no_attrs(), &[0; 32]);
    let member = Rec { kind: FNDSA512, key_data: fk.key.clone(), attrs: no_attrs(), pop: fk.sign(&scaas_ua::ua_message(FNDSA512, &ua8::pop_v2_tag(), &d).unwrap()), pqz_pop: vec![] };
    let (f, args) = member.job_args(&me);
    n.mined("P5 register the fndsa512 member, relayer mode", f, args).await;
    let (f, args) = ml_rec(&ml, &no_attrs(), &[0; 32], vec![]).job_args(&none);
    n.mined("P5 register the mldsa65 member", f, args).await;

    let mut list = vec![(FNDSA512, fk.ua, 1u16), (MLDSA65, ml.ua, 1)];
    list.sort_by_key(|m| m.1);
    let kd = scaas_ua::encode_msig(2, &list);
    let ua = scaas_ua::ua_of(MSIG, &kd).unwrap();
    let d = register_digest(MSIG, &ua, &no_attrs(), &[0; 32]);
    let slots: Vec<MemberSig> = list.iter().enumerate().map(|(i, m)| {
        let msg = member_message(m.0, &ua, &ua8::pop_v2_tag(), &d);
        MemberSig { index: i as u16, key_data: vec![], sig: if m.0 == FNDSA512 { fk.sign(&msg) } else { ml.sign(&msg) } }
    }).collect();
    let rec = Rec { kind: MSIG, key_data: kd, attrs: no_attrs(), pop: encode_member_sigs(&slots), pqz_pop: vec![] };

    // one bit of the fndsa512 slot: refused by `check_*`, before any simulation of the write, nothing signed
    let at = list.iter().position(|m| m.0 == FNDSA512).unwrap();
    let mut bad = slots.clone();
    bad[at].sig[40] ^= 1;
    let (f, args) = Rec { pop: encode_member_sigs(&bad), ..rec.clone() }.job_args(&me);
    let (state, last, tx) = n.run(0, call_job(&n.registry, f, args)).await;
    println!("P5 flipped fndsa512 slot: job {state}, reason {}", last["error"]);
    assert_eq!((state.as_str(), tx.is_none()), ("dead", true), "{last}");
    assert!(last["error"].as_str().unwrap_or_default().contains("UAPoP"), "{last}");
    // no relayer named: the chain cannot verify the slot
    let (f, args) = rec.job_args(&none);
    let (state, last, _) = n.run(0, call_job(&n.registry, f, args)).await;
    println!("P5 no relayer: job {state}, reason {}", last["error"]);
    assert_eq!(state, "dead", "{last}");

    let (f, args) = rec.job_args(&me);
    n.mined("P5 register_msig fndsa512 + mldsa65 slots, relayer mode", f, args).await;
    n.rec(&ua).await.eq("P5: Soroban against the arguments", &rec);
    let marks = n.checked_of(&ua).await;
    assert_eq!(marks[0], (2, Some(g(&key(0)))), "the record carries the lane's mark");

    // EVM verifies both slots: the signatures the node passed are the ones a chain accepts
    c.a.send("P5 register the fndsa512 member", member.calldata()).await;
    c.a.cache_key("P5 mldsa65 member", &ml.key).await;
    c.a.send("P5 register the mldsa65 member", ml_rec(&ml, &no_attrs(), &[0; 32], vec![]).calldata()).await;
    c.a.send("P5 registerMsig fndsa512 + mldsa65 slots", rec.calldata()).await;
    c.a.rec(&ua).await.eq("P5: EVM A against Soroban", &n.rec(&ua).await);
    println!("P5 result: an fndsa512 slot signed, passed check_registration, stored marked Relayer on Soroban and verified by EVM; remaining without a positive on a host: group vk slice, slhdsa128s slot, BLS slot with pop = false");
}
