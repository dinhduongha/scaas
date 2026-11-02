// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! UA-8 on Soroban (plan ua8-soroban B7, C15): a UA record copied EVM → Soroban → EVM byte for byte on a real Protocol 30
//! host and two anvil chains, and what only a real host can answer. `smartcontracts/soroban/scripts/e2e-ua8-local.sh` runs it
//! (env: see `soroban_common`, `UA8_EVM_A` / `UA8_EVM_B` = `<chain id>,<rpc url>`); `#[ignore]`, one test at a time.
//!
//! Every comparison is between independent sources: a chain's read against the vector or against the other chain's read,
//! never a value against its own copy. The registry writes go through the node's `call` jobs (`lane_step` on Soroban, the
//! outbox on EVM); only the published byte limits of `e2e_ua8_network_fit` use `raw_send`, junk `slhdsa128s` signatures the
//! off-chain check would refuse and the chain never reads. Log prefixes: `COPY`, `FIT`, `EDGE`, `FEE`, `BOUNDARY`, `ENTRY`, `P1` … `P5` (the brief's proofs).
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
use slh_dsa::{Sha2_128s, SigningKey as SlhKey};
use scaas_node::adapter::{lane_step, lane_step_metered, Built, ChainAdapter};
use scaas_node::adapters::soroban::{ua8_call_job, ua_metatx_job, RelayFeePolicy, SorobanAdapter};
use scaas_node::chain::Chain;
use scaas_node::breaker::Breaker;
use scaas_node::config::{BreakerCfg, ChainCfg, FinalityCfg};
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
    struct SolInnerSig { uint16 index; bytes sig; }
    struct SolMemberSig { uint16 index; SolInnerSig[] members; bytes sig; }
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
    event UARegistered(bytes32 indexed ua, uint16 indexed kind, bytes keyData, SolAttrs attrs, bytes32 popHash, bytes pqzPop, uint8 checkedPop, uint8 checkedPqzPop, uint8 checkedKem);
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

    /// The same call as a node job: entry and named fields, the node builds the calldata (typed-signing N1).
    fn evm_job(&self) -> (&'static str, Value) {
        let attrs = evm_attrs(&self.attrs);
        if self.kind == MSIG {
            let s = MsigStructure::from_key_data(&self.key_data).unwrap();
            let members: Vec<Value> = s.members.iter().map(|m| json!({"kind": m.kind, "id": h(&m.id), "weight": m.weight})).collect();
            let pop = evm_member_sigs(&decode_member_sigs(&self.pop).unwrap_or_default());
            ("registerMsig", json!({"structure": {"threshold": s.threshold, "members": members}, "attrs": attrs, "pop": pop, "pqzPop": "0x"}))
        } else {
            ("register", json!({"kind": self.kind, "keyData": h(&self.key_data), "attrs": attrs, "pop": h(&self.pop), "pqzPop": "0x"}))
        }
    }
}

fn evm_kem(k: &KemKey) -> Value {
    json!({"scheme": k.scheme, "mlkemEk": h(&k.mlkem_ek), "x25519": h(&k.x25519)})
}

fn evm_attrs(a: &UAAttrs) -> Value {
    json!({"pqzKey": h(&a.pqz_key), "pqzPopHash": h(&a.pqz_pop_hash), "kem": evm_kem(&a.kem), "kemPkHash": h(&a.kem_pk_hash)})
}

fn evm_member_sigs(m: &[MemberSig]) -> Vec<Value> {
    m.iter().map(|s| json!({"index": s.index, "members": [], "sig": h(&s.sig)})).collect()
}

/// A stored portable signature as an entry's named `UASig`.
fn evm_sig(kind: u16, stored: &[u8]) -> Value {
    if kind == MSIG {
        json!({"keyData": "0x", "signature": "0x", "members": evm_member_sigs(&decode_member_sigs(stored).unwrap())})
    } else {
        json!({"keyData": "0x", "signature": h(stored), "members": []})
    }
}

fn attrs_json(a: &UAAttrs) -> Value {
    json!({"pqz_key": h(&a.pqz_key), "pqz_pop_hash": h(&a.pqz_pop_hash), "kem": kem_json(&a.kem), "kem_pk_hash": h(&a.kem_pk_hash)})
}

fn kem_json(k: &KemKey) -> Value {
    json!({"scheme": k.scheme, "mlkem_ek": h(&k.mlkem_ek), "x25519": h(&k.x25519)})
}

fn member_sigs_json(m: &[MemberSig]) -> Vec<Value> {
    m.iter().map(|s| json!({"index": s.index, "key_data": "0x", "sig": h(&s.sig)})).collect()
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
    m.iter().map(|s| SolMemberSig { index: s.index, members: vec![], sig: s.sig.clone().into() }).collect()
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

/// What a failed transaction's diagnostic events say, `core_metrics` aside.
fn diagnostic_errors(r: &Value) -> Vec<String> {
    let xs = [&r["diagnosticEventsXdr"], &r["events"]["diagnosticEventsXdr"]].into_iter().filter_map(|v| v.as_array()).flatten();
    xs.filter_map(|x| DiagnosticEvent::from_xdr_base64(x.as_str().unwrap_or_default(), Limits::none()).ok())
        .map(|e| { let stellar_xdr::ContractEventBody::V0(b) = e.event.body; format!("{:?} {:?}", b.topics.as_slice(), b.data) })
        .filter(|t| !t.contains("core_metrics"))
        .map(|t| t.chars().take(220).collect())
        .collect()
}

/// `key_data` of the `UaRegistered` a landed transaction emitted, from its own event XDR.
fn registered_key_data(r: &Value) -> Vec<u8> {
    let events = r["events"]["contractEventsXdr"].as_array().into_iter().flatten().flat_map(|o| o.as_array().into_iter().flatten());
    for x in events {
        let e = stellar_xdr::ContractEvent::from_xdr_base64(x.as_str().unwrap(), Limits::none()).unwrap();
        let stellar_xdr::ContractEventBody::V0(b) = &e.body;
        if matches!(b.topics.first(), Some(ScVal::Symbol(s)) if s.0.as_slice() == b"UaRegistered") {
            return by(field(&tuple(&b.data)[0], "key_data"));
        }
    }
    panic!("no UaRegistered in {r}");
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

/// A member's acceptance as the node's `ua_metatx` job (CTR-UA-37).
fn accept_job(registry: &str, ua: &[u8; 32], slot: &MemberSig, relayer: &Value) -> Value {
    let id = JOB.fetch_add(1, Ordering::Relaxed);
    let member_sig = json!({"index": slot.index, "key_data": "0x", "sig": h(&slot.sig)});
    json!({"id": id, "kind": "ua_metatx", "op": {"contract": registry, "function": "accept_membership", "valid_until": now() + 600,
           "args": {"ua": h(ua), "member_sig": member_sig, "relayer": relayer}}})
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

    /// The lane's sequence. `getLedgerEntries` has answered `could not query captive core` once in a whole run, on a read that is
    /// not under test, so it gets a few tries here; the node's own lanes retry at their next step.
    async fn seq(&self, lane: usize) -> u64 {
        for _ in 0..4 {
            match self.adapter.sequence(lane).await {
                Ok(s) => return s,
                Err(e) => {
                    println!("RETRY sequence: {e:#}");
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
        self.adapter.sequence(lane).await.unwrap()
    }

    /// A transaction the node's checks do not see: `ua8_call_job`'s XDR, simulated as `build` does, sent if it simulates.
    /// `Err` is the refusal, at simulation or on chain.
    async fn raw_send(&self, what: &str, lane: usize, call: InvokeContractArgs, auth: Vec<SorobanAuthorizationEntry>) -> Result<String, String> {
        let (tx, r) = self.raw_tx(lane, call, auth).await?;
        if r["status"] != "SUCCESS" {
            println!("DIAG {what}: core_metrics {:?}; {:?}", core_metrics(&r), diagnostic_errors(&r));
            let size = TransactionEnvelope::from_xdr_base64(r["envelopeXdr"].as_str().unwrap(), Limits::none()).unwrap().to_xdr(Limits::none()).unwrap().len();
            return Err(format!("on chain, tx_size {size}: {} {}", r["status"], r["resultXdr"]));
        }
        fit(what, &tx).await;
        Ok(tx)
    }

    /// `raw_send`'s transaction, whatever it lands as: its hash and its `getTransaction` answer. `Err` = it never landed.
    async fn raw_tx(&self, lane: usize, call: InvokeContractArgs, auth: Vec<SorobanAuthorizationEntry>) -> Result<(String, Value), String> {
        let sim = simulate(lane as u32, call.clone(), auth.clone()).await;
        if let Some(e) = sim.get("error") {
            return Err(format!("simulation: {}", e.as_str().unwrap_or_default().chars().take(240).collect::<String>()));
        }
        let mut data = SorobanTransactionData::from_xdr_base64(sim["transactionData"].as_str().unwrap(), Limits::none()).unwrap();
        data.resource_fee += data.resource_fee * 15 / 100;
        let t = tx(lane as u32, 0, 100 + data.resource_fee as u32, call, auth, TransactionExt::V1(data));
        let seq = self.seq(lane).await;
        let built = Built { job_id: 0, body: t.to_xdr(Limits::none()).unwrap(), valid_until: 0, meta: json!({}) };
        let signed = self.adapter.sign(built, lane, seq).await.unwrap();
        let size = signed.raw.len();
        self.adapter.submit(&signed).await.map_err(|e| format!("sendTransaction, tx_size {size}: {e:#}"))?;
        let r = await_tx(&signed.tx_id).await;
        Ok((signed.tx_id, r))
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

    /// A client's own transaction (chain A), its gas logged. The `keyData` of a `UARegistered` it logged, if any.
    async fn send(&self, what: &str, data: Vec<u8>) -> Option<Vec<u8>> {
        let from: PrivateKeySigner = DEPLOYER_KEY.parse().unwrap();
        let p = ProviderBuilder::new().wallet(EthereumWallet::from(from)).connect_http(self.rpc.parse().unwrap());
        let r = p.send_transaction(TransactionRequest::default().to(self.registry).input(data.into())).await.unwrap().get_receipt().await.unwrap();
        assert!(r.status(), "{what}");
        println!("COPY evm {} {what}: gas_used {}", self.id, r.gas_used);
        r.inner.logs().iter().find_map(|l| l.log_decode::<UARegistered>().ok()).map(|l| l.inner.data.keyData.to_vec())
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
    async fn mined(&self, e: &Evm, what: &str, (entry, args): (&str, Value)) {
        let id = JOB.fetch_add(1, Ordering::Relaxed);
        let target = format!("{:#x}", e.registry);
        self.state.lock().unwrap().jobs.push(json!({"id": id, "kind": "call", "op": {"entry": entry, "token": target, "args": args, "validUntil": (now() + 600).to_string()}}));
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
        signers.iter().map(|&i| MemberSig { index: i as u16, members: vec![], sig: self.members[i].0.sign(&member_message(MLDSA65, &self.ua, purpose, digest)) }).collect()
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
    let evm_key = c.a.send(&format!("register {name}"), vector.calldata()).await.expect("UARegistered");
    if !vector.pqz_pop.is_empty() {
        c.a.send(&format!("storePqzPop {name}"), storePqzPopCall { ua: ua.into(), pqzPop: vector.pqz_pop.clone().into() }.abi_encode()).await;
    }
    let on_a = c.a.rec(&ua).await;
    on_a.eq(&format!("{name}: EVM A against the vector"), &vector);

    let (f, args) = on_a.job_args(relayer);
    let tx = c.s.mined(&format!("copy {f} {name}"), f, args).await;
    same(&format!("{name}: Soroban's UaRegistered against EVM's UARegistered"), "key_data", &registered_key_data(&await_tx(&tx).await), &evm_key);
    let on_s = c.s.rec(&ua).await;
    on_s.eq(&format!("{name}: Soroban against EVM A"), &on_a);

    c.lane_b.mined(&c.b, &format!("register {name}"), on_s.evm_job()).await;
    if !on_s.pqz_pop.is_empty() {
        c.lane_b.mined(&c.b, &format!("storePqzPop {name}"), ("storePqzPop", json!({"ua": h(&ua), "pqzPop": h(&on_s.pqz_pop)}))).await;
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

        c.lane_b.mined(&c.b, &format!("setKemKey {name} v{v}"), ("setKemKey", json!({"ua": h(&ua), "version": v.to_string(), "kem": evm_kem(&sk), "sig": evm_sig(rec.kind, &ssig)}))).await;
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

    c.lane_b.mined(&c.b, &format!("setPqzKey {record}"), ("setPqzKey", json!({"ua": h(&ua), "pqzKey": h(&skey), "pqzPopHash": h(&shash), "sig": evm_sig(rec.kind, &ssig)}))).await;
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
    c.lane_b.mined(&c.b, &format!("storePqzPop {record}"), ("storePqzPop", json!({"ua": h(&ua), "pqzPop": h(&spop)}))).await;
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
        index: i as u16, members: vec![],
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
    let (call, auth) = ua8_call_job(&network(), &op_of(&j), &lane, &registry, true).unwrap();
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
    let (call, auth) = ua8_call_job(&network(), &j["op"], &lane, &registry, true).unwrap();
    let ok = simulate(0, call, auth.clone()).await;
    let back = ok["results"][0]["auth"].as_array().cloned().unwrap_or_default();
    let same_entry = back.iter().all(|x| SorobanAuthorizationEntry::from_xdr_base64(x.as_str().unwrap(), Limits::none()).unwrap() == auth[0]);
    println!("P1 enforcing simulation that passes: {}, every entry returned is the node's own: {same_entry}", sim_answer(&ok));
    assert!(!back.is_empty() && same_entry, "an enforcing simulation answers the node's entry and nothing else");
    let changes = ok.get("stateChanges").and_then(|c| c.as_array()).map(|c| c.len());
    println!("P1 enforcing simulation, stateChanges: {changes:?} entries, of which with `after`: {:?}", ok.get("stateChanges").and_then(|c| c.as_array()).map(|c| c.iter().filter(|x| x["after"].is_string()).count()));

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
        // the heavy member is listed, the `pop` did not hold it (CTR-UA-37): the largest `Ua(ua)` an acceptance loads, one `mldsa65` slot
        let heavy_id = heavy.members[at].0.ua;
        let m = member_message(MLDSA65, &heavy.ua, &scaas_ua::purpose_tag("membership").unwrap(), &ua8::membership_digest(&heavy.ua, &heavy_id));
        let slot = MemberSig { index: at as u16, members: vec![], sig: heavy.members[at].0.sign(&m) };
        let (state, last, tx) = n.run(0, accept_job(&n.registry, &heavy.ua, &slot, &none)).await;
        assert_eq!(state, "mined", "{last}");
        fit(&format!("accept_membership Ua(ua) of 15 slots {set}, 1 slot"), &tx.unwrap()).await;
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
        let (call, auth) = ua8_call_job(&network(), &call_job(&n.registry, f, args)["op"], &lane, &registry, true).unwrap();
        n.raw_send(&format!("register slhdsa128s #{i}"), 0, call, auth).await.unwrap();
        members.push((SLHDSA128S, rec.ua(), 1u16));
    }
    members.sort_by_key(|m| m.1);
    let msig_of = |k: usize, c: usize| {
        let kd = scaas_ua::encode_msig(c as u16, &members[k..k + c]);
        let slots: Vec<MemberSig> = (0..c as u16).map(|index| MemberSig { index, members: vec![], sig: sig.clone() }).collect();
        Rec { kind: MSIG, key_data: kd, attrs: no_attrs(), pop: encode_member_sigs(&slots), pqz_pop: vec![] }
    };
    let relayed = |rec: &Rec| {
        let (f, args) = rec.job_args(&me);
        ua8_call_job(&network(), &call_job(&n.registry, f, args)["op"], &lane, &registry, true).unwrap()
    };
    for (c, fits) in [(7, true), (8, false)] {
        let (call, auth) = relayed(&msig_of(0, c));
        let r = n.raw_send(&format!("EDGE register_msig {c} slhdsa128s slots"), 0, call, auth).await;
        println!("EDGE register {c} slhdsa128s slots: {r:?}");
        assert_eq!(r.is_ok(), fits, "the published limit of register moved: {r:?}");
    }
    // `set_pqz_key`: the bytes rule, 6 slots at the smallest set and 5 at the largest
    for (k, c, set, fits) in [(1, 6, SETS[0], true), (1, 7, SETS[0], false), (2, 5, SETS[3], true), (2, 6, SETS[3], false)] {
        let (attrs, _, _) = set_attrs(set);
        let rec = msig_of(k, c);
        let (call, auth) = relayed(&rec);
        n.raw_send(&format!("register_msig {c} slhdsa128s slots ({set})"), 0, call, auth).await.unwrap();
        let args = json!({"ua": h(&rec.ua()), "pqz_key": h(&attrs.pqz_key), "pqz_pop_hash": h(&attrs.pqz_pop_hash), "sig": sig_json(MSIG, &rec.pop), "relayer": me});
        let (call, auth) = ua8_call_job(&network(), &call_job(&n.registry, "set_pqz_key", args)["op"], &lane, &registry, true).unwrap();
        let r = n.raw_send(&format!("EDGE set_pqz_key {c} slhdsa128s slots {set}"), 0, call, auth).await;
        println!("EDGE set_pqz_key {c} slhdsa128s slots at {set}: {r:?}");
        assert_eq!(r.is_ok(), fits, "the published limit of set_pqz_key moved: {r:?}");
    }
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
        let seq = n.seq(0).await;
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

    // through the node: a job whose transaction passes simulation and is over `tx_max_size_bytes`, a proof no entry could hold
    let big = vec![9; 140_000];
    let f = row("registrations", "fndsa512");
    let (mut attrs, _, _) = set_attrs(SETS[0]);
    attrs.pqz_pop_hash = scaas_ua::keccak256(&big);
    let rec = Rec { kind: FNDSA512, key_data: vec![0x77; 897], attrs, pop: hx(&f["pop"]), pqz_pop: vec![] };
    let (fun, args) = rec.job_args(&json!(g(&key(0))));
    assert!(table_row(&s, "register fndsa512 for the oversized job", fun, args).await);
    let job = call_job(&s.registry, "store_pqz_pop", json!({"ua": h(&rec.ua()), "pqz_pop": h(&big)}));
    let (state, last, tx) = s.run(0, job).await;
    println!("EDGE node, transaction over tx_max_size_bytes: job {state}, signed {}, reason {}", tx.is_some(), last["error"]);
    assert_eq!((state.as_str(), tx.is_none()), ("dead", true), "refused at build: {last}");
    assert!(last["error"].as_str().unwrap_or_default().contains("tx_max_size_bytes"), "{last}");

    // over the 65,536 B entry limit: one write, no signature to make, so what simulation answers is all that is measured
    let (lane, registry, me) = (sc(&g(&key(0))), sc(&s.registry), json!(g(&key(0))));
    let proof = vec![7; 70_000];
    let (attrs, _, _) = set_attrs(SETS[0]);
    let f = row("registrations", "fndsa512");
    let attrs = UAAttrs { pqz_pop_hash: scaas_ua::keccak256(&proof), ..attrs };
    let rec = Rec { kind: FNDSA512, key_data: hx(&f["keyData"]), attrs, pop: hx(&f["pop"]), pqz_pop: vec![] };
    let (fun, args) = rec.job_args(&me);
    let (call, auth) = ua8_call_job(&network(), &call_job(&s.registry, fun, args)["op"], &lane, &registry, true).unwrap();
    s.raw_send("register fndsa512 for the entry limit", 0, call, auth).await.unwrap();
    let job = call_job(&s.registry, "store_pqz_pop", json!({"ua": h(&rec.ua()), "pqz_pop": h(&proof)}));
    let (call, auth) = ua8_call_job(&network(), &job["op"], &lane, &registry, false).unwrap();
    let sim = simulate(0, call, auth).await;
    let data = SorobanTransactionData::from_xdr_base64(sim["transactionData"].as_str().unwrap_or_default(), Limits::none());
    let changes: Vec<usize> = sim["stateChanges"].as_array().into_iter().flatten()
        .filter_map(|c| c["after"].as_str()).map(|x| base64::Engine::decode(&base64::engine::general_purpose::STANDARD, x).unwrap().len()).collect();
    println!("ENTRY simulation of a 70,000 B write: error {:?}, write_bytes {:?}, stateChanges after {changes:?} B, fields {:?}",
             sim.get("error").is_some(), data.as_ref().map(|d| d.resources.write_bytes).ok(), sim.as_object().map(|o| o.keys().cloned().collect::<Vec<_>>()));
    let (state, last, tx) = s.run(0, job).await;
    println!("ENTRY the same job through the node: job {state}, signed {}, reason {}", tx.is_some(), last["error"]);
}

// ---------- B9a: the spend stop ----------

/// `i`'s native balance, read here and not through the adapter under test.
async fn native_balance(i: u32) -> u128 {
    let pk: [u8; 32] = key(i).public_key().try_into().unwrap();
    let id = stellar_xdr::AccountId(stellar_xdr::PublicKey::PublicKeyTypeEd25519(Uint256(pk)));
    let k = LedgerKey::Account(stellar_xdr::LedgerKeyAccount { account_id: id }).to_xdr_base64(Limits::none()).unwrap();
    let r = rpc("getLedgerEntries", json!({"keys": [k]})).await;
    match LedgerEntryData::from_xdr_base64(r["entries"][0]["xdr"].as_str().unwrap(), Limits::none()).unwrap() {
        LedgerEntryData::Account(a) => a.balance as u128,
        d => panic!("{d:?}"),
    }
}

/// A fresh record whose proof is `size` B, registered by lane 0 (`seed` makes it fresh): the `store_pqz_pop` job that writes it.
async fn pop_job(n: &Node, seed: u8, size: usize) -> Value {
    let proof = vec![seed; size];
    let (attrs, _, _) = set_attrs(SETS[0]);
    let attrs = UAAttrs { pqz_pop_hash: scaas_ua::keccak256(&proof), ..attrs };
    let rec = Rec { kind: FNDSA512, key_data: vec![seed; 897], attrs, pop: hx(&row("registrations", "fndsa512")["pop"]), pqz_pop: vec![] };
    let (f, args) = rec.job_args(&json!(g(&key(0))));
    assert!(table_row(n, &format!("register fndsa512 for a {size} B proof"), f, args).await);
    call_job(&n.registry, "store_pqz_pop", json!({"ua": h(&rec.ua()), "pqz_pop": h(&proof)}))
}

/// What the real host answers for the Soroban spend stop (NET-SOR-14): `tx_fee` against the balances, plain and fee-bumped,
/// `SUCCESS` and `FAILED`, whose `resultXdr` are the bytes of `adapters::soroban`'s tests; `lane_balance` of a funded and an
/// unfunded account; the entry limit's exact edge; a job over it refused at build.
#[tokio::test]
#[ignore]
async fn e2e_ua8_spend_stop() {
    let s = fresh_node().await;
    let registry = sc(&s.registry);
    let mut seed = 0x30;
    let mut landed = vec![];
    // lane 0 is the chain's `fee_bump_lane`, so with a fee bump lane 1 sends and lane 0 pays
    for (fee_bump, sender) in [(false, 0u32), (true, 1)] {
        let n = Node::with_fee_bump(s.registry.clone(), fee_bump).await;
        for (want, size) in [("SUCCESS", 1_000), ("FAILED", 70_000)] {
            seed += 1;
            let job = pop_job(&s, seed, size).await;
            let (call, auth) = ua8_call_job(&network(), &job["op"], &sc(&g(&key(sender))), &registry, false).unwrap();
            let before = (native_balance(0).await, native_balance(sender).await);
            let (tx, r) = n.raw_tx(sender as usize, call, auth).await.unwrap();
            let after = (native_balance(0).await, native_balance(sender).await);
            let res = stellar_xdr::TransactionResult::from_xdr_base64(r["resultXdr"].as_str().unwrap(), Limits::none()).unwrap();
            println!("FEE fee_bump {fee_bump} {}: feeCharged {}, payer (lane 0) down {}, sender (lane {sender}) down {}, feeBump {}, resultXdr {}",
                     r["status"], res.fee_charged, before.0 - after.0, before.1 - after.1, r["feeBump"], r["resultXdr"]);
            assert_eq!(r["status"], want, "{r}");
            landed.push((fee_bump, tx, before.0 - after.0));
        }
    }

    // the exact edge: every size around it landed, so the host answers, not a byte rule
    let (lane, mut edge) = (sc(&g(&key(0))), vec![]);
    for size in (65_392..=65_424).step_by(4) {
        seed += 1;
        let job = pop_job(&s, seed, size).await;
        let (call, auth) = ua8_call_job(&network(), &job["op"], &lane, &registry, false).unwrap();
        let sim = simulate(0, call.clone(), auth.clone()).await;
        let largest = sim["stateChanges"].as_array().into_iter().flatten().filter_map(|c| c["after"].as_str())
            .map(|x| base64::Engine::decode(&base64::engine::general_purpose::STANDARD, x).unwrap().len()).max().unwrap();
        let (_, r) = s.raw_tx(0, call, auth).await.unwrap();
        println!("BOUNDARY proof {size} B, after {largest} B: {} {:?}", r["status"], diagnostic_errors(&r).iter().take(1).collect::<Vec<_>>());
        edge.push((largest, r["status"].as_str().unwrap().to_string()));
    }

    let (at, over) = (edge.iter().filter(|e| e.1 == "SUCCESS").map(|e| e.0).max().unwrap(), edge.iter().filter(|e| e.1 == "FAILED").map(|e| e.0).min().unwrap());
    println!("BOUNDARY largest landed after {at} B, smallest refused after {over} B");

    // over the limit through the node: dead on the one claim, nothing signed
    let job = pop_job(&s, 0x7f, 70_000).await;
    let (state, last, tx) = s.run(0, job).await;
    println!("ENTRY over the limit through the node: job {state}, signed {}, reason {}", tx.is_some(), last["error"]);
    assert_eq!((state.as_str(), tx.is_none()), ("dead", true), "refused at build: {last}");
    assert!(last["error"].as_str().unwrap_or_default().contains("contract_data_entry_size_bytes"), "{last}");
    // the largest that lands still runs
    let job = pop_job(&s, 0x7e, at - 128).await;
    let (state, last, _) = s.run(0, job).await;
    println!("ENTRY at the limit through the node: job {state}, reason {}", last["error"]);
    assert_eq!(state, "mined", "{last}");

    // `meter` on the real host: a mined job through the node, the budget holding what left the lane
    let job = pop_job(&s, 0x7d, 1_000).await;
    let id = job["id"].as_i64().unwrap();
    s.state.lock().unwrap().jobs.push(job);
    let k = Mutex::new(Breaker::new(BreakerCfg { gas_budget_per_hour: Some(u128::MAX), ..Default::default() }));
    let before = native_balance(0).await;
    assert!(lane_step_metered(&s.adapter, &s.odoo, 0, "ua8#0", Some(&k)).await.unwrap());
    let down = before - native_balance(0).await;
    let (spent, unread) = { let k = k.lock().unwrap(); (k.spent(), k.fees_unread()) };
    println!("FEE metered through the node: job {}, budget spent {spent}, lane down {down}", last_state(&s.state.lock().unwrap(), id));
    assert_eq!((spent, unread), (down, 0), "the budget holds this job's fee");
    assert!(down > 0);

    let unfunded = SorobanAdapter::new(&chain_cfg(false), &[key(20), key(21)]).unwrap();
    assert_eq!(unfunded.lane_balance(0).await.unwrap(), Some(0), "no account, no balance");
    let n = Node::with_fee_bump(s.registry.clone(), true).await;
    let (b0, b1) = (native_balance(0).await, native_balance(1).await);
    assert_eq!(s.adapter.lane_balance(1).await.unwrap(), Some(b1));
    assert_eq!(n.adapter.lane_balance(1).await.unwrap(), Some(b0), "under a fee bump, the account that pays");
    assert_eq!(n.adapter.lane_balance(0).await.unwrap(), Some(b0), "the fee account's own lane");
    for (fee_bump, tx, down) in landed {
        let a = if fee_bump { &n.adapter } else { &s.adapter };
        assert_eq!(a.tx_fee(&tx).await.unwrap(), Some(down), "feeCharged is what left the payer");
    }
}

// ---------- B7b: relayer mode, before and after the argument hash ----------

/// One row of the table: every relayer-mode write as `raw_send` (junk signatures of the kind's length, which the chain stores
/// unread), logged by name. The same test measured the contract before the owner's change of 2026-11-01, so a row's size is
/// comparable across the two logs in `runs/`.
async fn table_row(n: &Node, name: &str, f: &str, args: Value) -> bool {
    let (lane, registry) = (sc(&g(&key(0))), sc(&n.registry));
    let (call, auth) = ua8_call_job(&network(), &call_job(&n.registry, f, args)["op"], &lane, &registry, true).unwrap();
    match n.raw_send(&format!("TABLE {name}"), 0, call, auth).await {
        Ok(_) => true,
        Err(e) => {
            println!("FIT TABLE {name}: REFUSED {}", e.chars().take(170).collect::<String>().replace('\n', " "));
            false
        }
    }
}

/// A slot kind's registered members, junk signatures of its length.
struct Pool {
    name: &'static str,
    kind: u16,
    sig: Vec<u8>,
    ids: Vec<[u8; 32]>,
}

impl Pool {
    async fn new(n: &Node, name: &'static str, kind: u16, key: usize, sig: usize, count: u8) -> Pool {
        let (me, mut ids) = (json!(g(&key_of_lane())), vec![]);
        for i in 0..count {
            let rec = Rec { kind, key_data: vec![0x20 + i; key], attrs: no_attrs(), pop: vec![0x5a; sig], pqz_pop: vec![] };
            let (f, args) = rec.job_args(&me);
            assert!(table_row(n, &format!("register {name} no attributes #{i}"), f, args).await, "{name} #{i}");
            ids.push(rec.ua());
        }
        ids.sort();
        Pool { name, kind, sig: vec![0x5a; sig], ids }
    }

    fn slots(&self, indexes: impl Iterator<Item = u16>) -> Vec<MemberSig> {
        indexes.map(|index| MemberSig { index, members: vec![], sig: self.sig.clone() }).collect()
    }

    /// `count` members from `start`, every one needed: `extra` on one weight only tells two records of the same members apart.
    fn all_of(&self, start: usize, count: usize, extra: u16, attrs: &UAAttrs, pqz_pop: Vec<u8>) -> Rec {
        let list: Vec<_> = self.ids[start..start + count].iter().enumerate().map(|(i, id)| (self.kind, *id, 1 + if i == 0 { extra } else { 0 })).collect();
        let key_data = scaas_ua::encode_msig(count as u16 + extra, &list);
        Rec { kind: MSIG, key_data, attrs: attrs.clone(), pop: encode_member_sigs(&self.slots(0..count as u16)), pqz_pop }
    }

    /// `count` members needed for a later record and one heavy member: a later write's size does not need a `register` of the same
    /// size. Only an accepted slot writes (CTR-UA-37), so up to `edge` the light members sign the `pop` and past it the heavy member
    /// registers alone and `accept_all` follows. `(record, the later record's slots)`.
    fn light_and_heavy(&self, start: usize, count: usize, weight: u16, edge: usize) -> (Rec, Vec<MemberSig>) {
        let mut list: Vec<_> = self.ids[start..start + count].iter().map(|id| (self.kind, *id, 1u16)).collect();
        list.push((self.kind, self.ids[start + count], count as u16 + weight));
        let key_data = scaas_ua::encode_msig(count as u16, &list);
        let at = count as u16; // sorted: the pool is, and the heavy member is the last of the slice
        let pop = if count <= edge { self.slots(0..at) } else { self.slots(at..at + 1) };
        let rec = Rec { kind: MSIG, key_data, attrs: no_attrs(), pop: encode_member_sigs(&pop), pqz_pop: vec![] };
        (rec, self.slots(0..count as u16))
    }
}

/// Each slot's acceptance on the lane's word: the node's own XDR past its off-chain check, as `table_row`, a slot here being junk bytes.
async fn accept_all(n: &Node, ua: &[u8; 32], slots: &[MemberSig]) {
    let lane = sc(&g(&key(0)));
    let mut cfg = chain_cfg(false);
    cfg.params.insert("ua_registry".into(), n.registry.clone().into());
    let policy = RelayFeePolicy::from_cfg(&cfg).unwrap();
    policy.relayers.set(vec![lane.clone()]).unwrap();
    for s in slots {
        let (call, auth, _) = ua_metatx_job(&network(), &accept_job(&n.registry, ua, s, &json!(g(&key(0))))["op"], &lane, &policy).unwrap();
        n.raw_send(&format!("ACCEPT slot {} of {} B", s.index, s.sig.len()), 0, call, auth).await.unwrap();
    }
}

fn key_of_lane() -> scaas_node::signer::LocalSigner {
    key(0)
}

/// B8's table: every relayer-mode write's transaction, and the slot limits per set per kind, the edge and one refused, asserted.
#[tokio::test]
#[ignore]
async fn e2e_ua8_relayer_table() {
    network_limits().await;
    let n = fresh_node().await;
    let me = json!(g(&key(0)));
    let kem1 = KemKey::from_kem_pk(&hx(&row("kemRecords", "mldsa65/v1")["kemPk"])).unwrap();
    let slh = Pool::new(&n, "slhdsa128s", SLHDSA128S, 32, 7_856, 13).await;
    let fnd = Pool::new(&n, "fndsa512", FNDSA512, 897, 666, 20).await;

    // single keys and the two group kinds
    for (r, set) in SETS.iter().enumerate() {
        let (attrs, proof, _) = set_attrs(set);
        let single = |i: u8, attrs: &UAAttrs, pqz_pop: Vec<u8>| Rec { kind: FNDSA512, key_data: vec![0x60 + i; 897], attrs: attrs.clone(), pop: vec![0x5a; 666], pqz_pop };
        let (f, args) = single(4 * r as u8, &attrs, vec![]).job_args(&me);
        table_row(&n, &format!("register fndsa512 + PQZ + KEM {set}"), f, args).await;
        let (f, args) = single(4 * r as u8 + 1, &attrs, proof.clone()).job_args(&me);
        table_row(&n, &format!("register fndsa512 + PQZ + KEM + proof {set}"), f, args).await;
        let bare = single(4 * r as u8 + 2, &no_attrs(), vec![]);
        let (f, args) = bare.job_args(&me);
        table_row(&n, &format!("register fndsa512 for later writes {set}"), f, args).await;
        let sig = sig_json(FNDSA512, &[0x5a; 666]);
        table_row(&n, &format!("set_pqz_key fndsa512 {set}"), "set_pqz_key", json!({"ua": h(&bare.ua()), "pqz_key": h(&attrs.pqz_key), "pqz_pop_hash": h(&attrs.pqz_pop_hash), "sig": sig, "relayer": me})).await;
        table_row(&n, &format!("set_kem_key fndsa512 {set}"), "set_kem_key", json!({"ua": h(&bare.ua()), "version": 1, "kem": kem_json(&kem1), "sig": sig, "relayer": me})).await;
    }
    let point = |i: u8| h(&[0x40 + i; 64]);
    table_row(&n, "register_musig2 bn254 16 keys", "register_musig2", json!({"kind": 0x0112, "key": {"agg_key": point(0), "member_keys": (1..17).map(point).collect::<Vec<_>>()},
        "attrs": attrs_json(&no_attrs()), "pop": h(&[0x5a; 64]), "pqz_pop": "0x", "relayer": me})).await;
    for t in [12u8, 13, 14, 15, 16] {
        let member = |i: u8| json!({"commitments": (0..t).map(|c| point(i + c)).collect::<Vec<_>>(), "r": point(i), "z": h(&[i; 32])});
        let ok = table_row(&n, &format!("register_frost bn254 {t} of 16"), "register_frost", json!({"kind": 0x0113, "key": {"group_key": point(99 + t), "threshold": t, "members": (0..16).map(member).collect::<Vec<_>>()},
            "attrs": attrs_json(&no_attrs()), "pop": h(&[0x5a; 64]), "pqz_pop": "0x", "relayer": me})).await;
        assert!(ok, "register_frost {t} of 16");
    }

    // `msig` slots per set per kind: `register` with attributes, then the two later writes
    for (si, set) in SETS.iter().enumerate() {
        let (attrs, proof, _) = set_attrs(set);
        let slh_pqz = [6, 5, 5, 5][si];
        let cases = [(&slh, &[5usize, 6, 7, 8][..], 7usize, &[1usize, 5, 7, 8][..], &[4usize, 5, 6, 7][..], slh_pqz, &[7usize, 8][..], 7usize),
                     (&fnd, &[16, 17][..], 16, &[8, 16, 17][..], &[15][..], 15, &[15][..], 15)];
        for (pool, plain, edge, whole, pqz, pqz_edge, kem, kem_edge) in cases {
            let name = pool.name;
            for &c in plain {
                let (f, args) = pool.all_of(si, c, 0, &attrs, vec![]).job_args(&me);
                let ok = table_row(&n, &format!("register_msig {c} {name} slots + PQZ + KEM {set}"), f, args).await;
                assert_eq!(ok, c <= edge, "register_msig {c} {name} + PQZ + KEM at {set}: the limit moved");
            }
            for &c in whole {
                let (f, args) = pool.all_of(si, c, 1, &attrs, proof.clone()).job_args(&me);
                let ok = table_row(&n, &format!("register_msig {c} {name} slots + PQZ + KEM + proof {set}"), f, args).await;
                assert_eq!(ok, c <= edge, "register_msig {c} {name} + PQZ + KEM + proof at {set}: the limit moved");
            }
            for &c in pqz {
                let (rec, slots) = pool.light_and_heavy(si, c, 1, edge);
                let (f, args) = rec.job_args(&me);
                assert!(table_row(&n, &format!("register_msig heavy member, {c} light {name} {set}"), f, args).await);
                let ok = table_row(&n, &format!("set_pqz_key {c} {name} slots {set}"), "set_pqz_key", json!({"ua": h(&rec.ua()), "pqz_key": h(&attrs.pqz_key), "pqz_pop_hash": h(&attrs.pqz_pop_hash),
                    "sig": sig_json(MSIG, &encode_member_sigs(&slots)), "relayer": me})).await;
                assert_eq!(ok, c <= pqz_edge, "set_pqz_key {c} {name} at {set}: the limit moved");
            }
            for &c in kem {
                let (rec, slots) = pool.light_and_heavy(si, c, 2, edge);
                let (f, args) = rec.job_args(&me);
                assert!(table_row(&n, &format!("register_msig heavy member, {c} light {name} for KEM {set}"), f, args).await);
                if c > edge {
                    accept_all(&n, &rec.ua(), &slots).await;
                }
                let ok = table_row(&n, &format!("set_kem_key {c} {name} slots {set}"), "set_kem_key", json!({"ua": h(&rec.ua()), "version": 1, "kem": kem_json(&kem1),
                    "sig": sig_json(MSIG, &encode_member_sigs(&slots)), "relayer": me})).await;
                assert_eq!(ok, c <= kem_edge, "set_kem_key {c} {name} at {set}: the limit moved");
            }
        }
        // every member signing: the 16-member structure is the edge of a `fndsa512` slot, 17 members are refused above
        let rec = fnd.all_of(si, 16, 2, &no_attrs(), vec![]);
        let (f, args) = rec.job_args(&me);
        assert!(table_row(&n, &format!("register_msig 16 fndsa512 slots, no attributes {set}"), f, args).await);
        assert!(table_row(&n, &format!("set_pqz_key 16 fndsa512 slots {set}"), "set_pqz_key", json!({"ua": h(&rec.ua()), "pqz_key": h(&attrs.pqz_key), "pqz_pop_hash": h(&attrs.pqz_pop_hash),
            "sig": sig_json(MSIG, &rec.pop), "relayer": me})).await);
        assert!(table_row(&n, &format!("set_kem_key 16 fndsa512 slots {set}"), "set_kem_key", json!({"ua": h(&rec.ua()), "version": 1, "kem": kem_json(&kem1), "sig": sig_json(MSIG, &rec.pop), "relayer": me})).await);
    }

    // `Chain` parts with a relayer named: the unused entry
    let ml: Vec<Ml> = (0..16).map(|i| Ml::new(0xa0 + i)).collect();
    for (i, m) in ml.iter().enumerate() {
        let (f, args) = ml_rec(m, &no_attrs(), &[0; 32], vec![]).job_args(&me);
        table_row(&n, &format!("register mldsa65 Chain, relayer named #{i}"), f, args).await;
    }
    let (attrs, proof, pqz_hash) = set_attrs(SETS[3]);
    let m16 = Ms::new(16, ml.iter().map(|m| (m, 1)).collect());
    let (f, args) = m16.rec(&m16.every(), &attrs, &pqz_hash, proof).job_args(&me);
    assert!(table_row(&n, "register_msig n=16 mldsa65 Chain + PQZ + KEM + proof n2816-kmax65536, relayer named", f, args).await, "naming a relayer no longer doubles it");
}

/// Simulated on the real host: the node's entry for `a` under the call of `b`.
async fn entry_for_other_args(n: &Node, a: &Value, b: &Value) -> Value {
    let (lane, registry) = (sc(&g(&key(0))), sc(&n.registry));
    let (_, auth) = ua8_call_job(&network(), a, &lane, &registry, true).unwrap();
    let (call, _) = ua8_call_job(&network(), b, &lane, &registry, true).unwrap();
    simulate(0, call, auth).await
}

fn job_of(n: &Node, f: &str, args: Value) -> Value {
    call_job(&n.registry, f, args)["op"].clone()
}

/// `a`'s own entry passes on the real host, and `b`'s does not pass for `a`: the contract's digest is the node's, on these bytes.
async fn binds_on_host(n: &Node, what: &str, a: &Value, b: &Value) {
    let own = entry_for_other_args(n, b, b).await;
    assert!(own.get("error").is_none(), "{what}: the changed write on its own entry: {}", own["error"]);
    let other = entry_for_other_args(n, a, b).await;
    let refused = other["error"].as_str().unwrap_or_default().contains("Error(Auth,");
    println!("BIND {what}: own entry passes, the entry of other arguments {}", if refused { "REFUSED Error(Auth)" } else { "PASSED" });
    assert!(refused, "{what}: {}", sim_answer(&other));
}

fn flip_field(v: &mut Value) {
    let mut b = hx(v);
    let i = b.len() / 2;
    b[i] ^= 1;
    *v = json!(h(&b));
}

/// Owner 2026-11-01, on the real host: the entry of one argument set passes for no other, each class changed alone; a hash of
/// another entry is refused; `Some(lane)` and the listed relayer's own auth are still needed. What holds an entry to its
/// registry and network: `SourceAccount` signs nothing of its own, the transaction's signature covers it.
#[tokio::test]
#[ignore]
async fn e2e_ua8_attestation_binds() {
    let n = fresh_node().await;
    let me = json!(g(&key(0)));
    let (lane, registry) = (sc(&g(&key(0))), sc(&n.registry));
    let (attrs, proof, _) = set_attrs(SETS[0]);
    let f = row("registrations", "fndsa512");

    // `register`
    let rec = Rec { kind: FNDSA512, key_data: vec![0x31; 897], attrs: attrs.clone(), pop: hx(&f["pop"]), pqz_pop: proof.clone() };
    let (fun, args) = rec.job_args(&me);
    let base = job_of(&n, fun, args.clone());
    let changed = |path: &[&str]| {
        let mut o = base.clone();
        let mut v = &mut o["args"];
        for p in path {
            v = &mut v[*p];
        }
        flip_field(v);
        o
    };
    for (what, path) in [("key_data", &["key_data"][..]), ("pop", &["pop"]), ("attrs.pqz_key", &["attrs", "pqz_key"]), ("attrs.kem.mlkem_ek", &["attrs", "kem", "mlkem_ek"]), ("attrs.kem.x25519", &["attrs", "kem", "x25519"])] {
        binds_on_host(&n, &format!("register {what}"), &base, &changed(path)).await;
    }
    let mut o = base.clone();
    o["args"]["pqz_pop"] = json!("0x");
    binds_on_host(&n, "register pqz_pop", &base, &o).await;
    let mut o = base.clone();
    o["args"]["attrs"]["pqz_pop_hash"] = json!(h(&scaas_ua::keccak256(&[7; 8])));
    o["args"]["pqz_pop"] = json!(h(&[7; 8]));
    binds_on_host(&n, "register attrs.pqz_pop_hash", &base, &o).await;
    let (k1, k2) = (json!({"kind": SLHDSA128S, "key_data": h(&[3; 32]), "attrs": attrs_json(&no_attrs()), "pop": h(&[1; 8]), "pqz_pop": "0x", "relayer": me}), 0x0103);
    let mut k = k1.clone();
    k["kind"] = json!(k2);
    binds_on_host(&n, "register kind", &job_of(&n, "register", k1), &job_of(&n, "register", k)).await;

    // refused for what it is, not for what it asks: `None` on the same record, the other lane's name, no entry at all
    let (call, _) = ua8_call_job(&network(), &base, &lane, &registry, true).unwrap();
    let mut none = base.clone();
    none["args"]["relayer"] = Value::Null;
    let (no_relayer, no_entry) = ua8_call_job(&network(), &none, &lane, &registry, true).unwrap();
    assert!(no_entry.is_empty());
    let r = simulate(0, no_relayer, vec![]).await;
    println!("BIND relayer = None: {}", sim_answer(&r));
    assert!(r["error"].as_str().unwrap_or_default().contains("#11"), "NotVerifiable");
    let (_, auth) = ua8_call_job(&network(), &base, &lane, &registry, true).unwrap();
    let r = simulate(1, call.clone(), auth.clone()).await;
    println!("BIND the entry sent by another source than the named relayer: {}", sim_answer(&r));
    assert!(r["error"].as_str().unwrap_or_default().contains("Error(Auth,"), "the named relayer's auth is needed");

    // a hash of another entry, the right function name over it; the entry on another registry
    let word = |network_id: &[u8; 32], contract: &ScAddress, digest_of: &str, on: &ScSymbol, at: &ScAddress| {
        let d = scaas_node::adapters::soroban::attest_digest(network_id, contract, &sym(digest_of), &call.args).unwrap();
        let root = InvokeContractArgs { contract_address: at.clone(), function_name: on.clone(), args: vec![sc_bytes(&d)].try_into().unwrap() };
        SorobanAuthorizationEntry {
            credentials: stellar_xdr::SorobanCredentials::SourceAccount,
            root_invocation: stellar_xdr::SorobanAuthorizedInvocation { function: stellar_xdr::SorobanAuthorizedFunction::ContractFn(root), sub_invocations: Default::default() },
        }
    };
    let other = sc(&deploy_sh("ua_registry", &secret(DEPLOYER), &["--relayers", &format!("[\"{}\"]", g(&key(0)))]));
    let cases = [
        ("a digest of set_kem_key, on register", word(&network(), &registry, "set_kem_key", &sym("register"), &registry)),
        ("a digest of register_msig, on register", word(&network(), &registry, "register_msig", &sym("register"), &registry)),
        ("a digest of register, on set_kem_key", word(&network(), &registry, "register", &sym("set_kem_key"), &registry)),
        ("a digest of register at another registry", word(&network(), &other, "register", &sym("register"), &registry)),
        ("this digest, on another registry", word(&network(), &registry, "register", &sym("register"), &other)),
        ("a digest of register on another network", word(&[0x11; 32], &registry, "register", &sym("register"), &registry)),
    ];
    for (what, e) in cases {
        let r = simulate(0, call.clone(), vec![e]).await;
        println!("BIND {what}: {}", sim_answer(&r));
        assert!(r["error"].as_str().unwrap_or_default().contains("Error(Auth,"), "{what}");
    }
    // the network: a `SourceAccount` entry has no preimage, the transaction's signature is what names the network
    let mut cfg = chain_cfg(false);
    cfg.params.insert("network_passphrase".into(), "Another network".into());
    let foreign = SorobanAdapter::new(&cfg, &[key(0), key(1)]).unwrap();
    let sim = simulate(0, call.clone(), auth.clone()).await;
    let mut data = SorobanTransactionData::from_xdr_base64(sim["transactionData"].as_str().unwrap(), Limits::none()).unwrap();
    data.resource_fee += data.resource_fee * 15 / 100;
    let t = tx(0, 0, 100 + data.resource_fee as u32, call.clone(), auth.clone(), TransactionExt::V1(data));
    let built = Built { job_id: 0, body: t.to_xdr(Limits::none()).unwrap(), valid_until: 0, meta: json!({}) };
    let signed = foreign.sign(built, 0, n.adapter.sequence(0).await.unwrap()).await.unwrap();
    let sent = n.adapter.submit(&signed).await;
    println!("BIND the same transaction signed for another network: {sent:?}");
    assert!(sent.is_err(), "refused before any entry is read");

    // the base write itself lands, marked, and authorises nothing
    assert!(table_row(&n, "register fndsa512, its entry", fun, args).await);
    assert_eq!(n.checked_of(&rec.ua()).await[0], (2, Some(g(&key(0)))));
    n.rec(&rec.ua()).await.eq("BIND: Soroban against the arguments", &rec);
    assert_eq!(read(&n.registry, "receivable", vec![sc_bytes(&rec.ua())]).await, ScVal::Bool(false));
    let ua = rec.ua();

    // `set_kem_key`, `set_pqz_key`
    let kem1 = KemKey::from_kem_pk(&hx(&row("kemRecords", "mldsa65/v1")["kemPk"])).unwrap();
    let sig = sig_json(FNDSA512, &[0x5a; 666]);
    let kem_base = job_of(&n, "set_kem_key", json!({"ua": h(&ua), "version": 1, "kem": kem_json(&kem1), "sig": sig, "relayer": me}));
    let flipped = |base: &Value, path: &[&str]| {
        let mut o = base.clone();
        let mut v = &mut o["args"];
        for p in path {
            v = &mut v[*p];
        }
        flip_field(v);
        o
    };
    for (what, path) in [("kem.mlkem_ek", &["kem", "mlkem_ek"][..]), ("kem.x25519", &["kem", "x25519"]), ("sig.signature", &["sig", "signature"])] {
        binds_on_host(&n, &format!("set_kem_key {what}"), &kem_base, &flipped(&kem_base, path)).await;
    }
    let mut v2 = kem_base.clone();
    v2["args"]["version"] = json!(2);
    binds_on_host(&n, "set_kem_key version", &kem_base, &v2).await;
    let bare = Rec { kind: FNDSA512, key_data: vec![0x32; 897], attrs: no_attrs(), pop: hx(&f["pop"]), pqz_pop: vec![] };
    let (fun, args) = bare.job_args(&me);
    assert!(table_row(&n, "register fndsa512, a second holder", fun, args).await);
    let mut u2 = kem_base.clone();
    u2["args"]["ua"] = json!(h(&bare.ua()));
    binds_on_host(&n, "set_kem_key ua", &kem_base, &u2).await;
    let pqz_base = job_of(&n, "set_pqz_key", json!({"ua": h(&bare.ua()), "pqz_key": h(&attrs.pqz_key), "pqz_pop_hash": h(&attrs.pqz_pop_hash), "sig": sig, "relayer": me}));
    for (what, path) in [("pqz_key", &["pqz_key"][..]), ("pqz_pop_hash", &["pqz_pop_hash"]), ("sig.signature", &["sig", "signature"])] {
        binds_on_host(&n, &format!("set_pqz_key {what}"), &pqz_base, &flipped(&pqz_base, path)).await;
    }
    let third = Rec { key_data: vec![0x33; 897], ..bare.clone() };
    let (fun, args) = third.job_args(&me);
    assert!(table_row(&n, "register fndsa512, a third holder", fun, args).await);
    let mut u2 = pqz_base.clone();
    u2["args"]["ua"] = json!(h(&third.ua()));
    binds_on_host(&n, "set_pqz_key ua", &pqz_base, &u2).await;

    // `register_msig`, a slot and the structure
    let slh = Pool::new(&n, "slhdsa128s", SLHDSA128S, 32, 7_856, 3).await;
    let m = slh.all_of(0, 2, 0, &no_attrs(), vec![]);
    let (fun, args) = m.job_args(&me);
    let base = job_of(&n, fun, args);
    let m2 = slh.all_of(1, 2, 0, &no_attrs(), vec![]);
    let (fun, args) = m2.job_args(&me);
    binds_on_host(&n, "register_msig structure.members", &base, &job_of(&n, fun, args)).await;
    let mut o = base.clone();
    flip_field(&mut o["args"]["pop"][0]["sig"]);
    binds_on_host(&n, "register_msig pop.sig", &base, &o).await;
}

/// Owner 2026-11-01, CTR-UA-33.A on Soroban: every `frost-bn254` shape registers on the real host. A key over 15,360 B leaves the
/// event and nothing else: its `ua` is the key's, `registration_of` returns it byte for byte. Threshold 1 exists on no chain.
#[tokio::test]
#[ignore]
async fn e2e_ua8_frost_every_size() {
    let n = fresh_node().await;
    let me = json!(g(&key(0)));
    let (lane, registry) = (sc(&g(&key(0))), sc(&n.registry));
    let (mut carried, mut emptied) = (0, vec![]);
    let frost = |t: u8, count: u8| {
        let point = |x: u8| vec![x; 64];
        let group = [vec![t; 32], vec![count; 32]].concat();
        let mut kd = [group.clone(), vec![0, t, 0, count]].concat();
        let members: Vec<Value> = (0..count).map(|i| {
            let commitments: Vec<Vec<u8>> = (0..t).map(|c| point(0x40 + c)).collect();
            let (r, z) = (point(0x60 + i), vec![0x80 + i; 32]);
            kd.extend(commitments.concat());
            kd.extend(&r);
            kd.extend(&z);
            json!({"commitments": commitments.iter().map(|c| h(c)).collect::<Vec<_>>(), "r": h(&r), "z": h(&z)})
        }).collect();
        (json!({"kind": 0x0113, "key": {"group_key": h(&group), "threshold": t, "members": members}, "attrs": attrs_json(&no_attrs()), "pop": h(&[0x5a; 64]), "pqz_pop": "0x", "relayer": me}), kd)
    };
    for t in 2..=16u8 {
        for count in t..=16u8 {
            let (args, kd) = frost(t, count);
            let name = format!("register_frost bn254 {t} of {count}, key_data {} B", kd.len());
            let (call, auth) = ua8_call_job(&network(), &call_job(&n.registry, "register_frost", args)["op"], &lane, &registry, true).unwrap();
            let tx = n.raw_send(&name, 0, call, auth).await.unwrap_or_else(|e| panic!("{name}: {e}"));
            let got = registered_key_data(&await_tx(&tx).await);
            let rec = Rec { kind: 0x0113, key_data: kd.clone(), attrs: no_attrs(), pop: vec![0x5a; 64], pqz_pop: vec![] };
            n.rec(&rec.ua()).await.eq(&name, &rec);
            if kd.len() <= 15_360 {
                same(&name, "the event's key_data", &got, &kd);
                carried += 1;
            } else {
                assert!(got.is_empty(), "{name}: {} B in the event", got.len());
                emptied.push(format!("{t} of {count}"));
                println!("EVENT {name}: emptied, the record byte-equal");
            }
        }
    }
    println!("EVENT carried {carried}, emptied {emptied:?}");
    assert_eq!(emptied, ["14 of 16", "15 of 15", "15 of 16", "16 of 16"]);
    assert_eq!(carried, 116);
    for (t, count) in [(1, 1), (1, 2), (1, 16)] {
        let (args, _) = frost(t, count);
        let (call, auth) = ua8_call_job(&network(), &call_job(&n.registry, "register_frost", args)["op"], &lane, &registry, true).unwrap();
        let r = simulate(0, call, auth).await;
        println!("EVENT threshold 1 of {count}: {}", sim_answer(&r));
        assert!(r["error"].as_str().unwrap_or_default().contains("#2"), "KeyData: EVM and ua-rs refuse it too");
    }
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

/// A seeded `slhdsa128s` key (FIPS 205 internal functions, no rng), signing what the kind signs: `signed_message`.
struct Slh {
    key: Vec<u8>,
    ua: [u8; 32],
    sk: SlhKey<Sha2_128s>,
}

impl Slh {
    fn new(seed: u8) -> Slh {
        let sk = SlhKey::<Sha2_128s>::slh_keygen_internal(&[seed; 16], &[seed ^ 0x55; 16], &[seed ^ 0xaa; 16]);
        let vk: &slh_dsa::VerifyingKey<Sha2_128s> = sk.as_ref();
        let key = vk.to_bytes().as_slice().to_vec();
        Slh { ua: scaas_ua::ua_of(SLHDSA128S, &key).unwrap(), key, sk }
    }

    fn sign(&self, ua_msg: &[u8; 32]) -> Vec<u8> {
        let m = scaas_ua::pq::signed_message(SLHDSA128S, ua_msg);
        // M' = 0x00 || ctx length 0 || m
        self.sk.slh_sign_internal(&[&[0u8, 0][..], &m[..]], None).to_bytes().as_slice().to_vec()
    }
}

/// P5: a mixed `msig`, one `fndsa512` slot, one `mldsa65` slot and one `slhdsa128s` slot, all signing, end to end: `register` of the `fndsa512` member by
/// its real `pop`, `ua8_precheck` reading the members from the chain and running `check_registration` over the real signature
/// (the group `vk` slice of `signature_ok` and a BLS slot with `pop = false` have no positive on a host). The same record is also
/// accepted by EVM, which verifies both slots itself, so the node's positive is not its own opinion.
#[tokio::test]
#[ignore]
async fn e2e_ua8_relayer_checked_msig_slot() {
    let c = copy_stack().await;
    // this test's own fake Odoo: the stack's runs on the runtime of the test that made it
    let n = Node::new(c.s.registry.clone()).await;
    let (me, none) = (json!(g(&key(0))), Value::Null);
    let (fk, ml, sl) = (Falcon::new(), Ml::new(0x33), Slh::new(0x44));
    let d = register_digest(FNDSA512, &fk.ua, &no_attrs(), &[0; 32]);
    let member = Rec { kind: FNDSA512, key_data: fk.key.clone(), attrs: no_attrs(), pop: fk.sign(&scaas_ua::ua_message(FNDSA512, &ua8::pop_v2_tag(), &d).unwrap()), pqz_pop: vec![] };
    let (f, args) = member.job_args(&me);
    n.mined("P5 register the fndsa512 member, relayer mode", f, args).await;
    let (f, args) = ml_rec(&ml, &no_attrs(), &[0; 32], vec![]).job_args(&none);
    n.mined("P5 register the mldsa65 member", f, args).await;

    let d = register_digest(SLHDSA128S, &sl.ua, &no_attrs(), &[0; 32]);
    let slh_member = Rec { kind: SLHDSA128S, key_data: sl.key.clone(), attrs: no_attrs(), pop: sl.sign(&scaas_ua::ua_message(SLHDSA128S, &ua8::pop_v2_tag(), &d).unwrap()), pqz_pop: vec![] };
    let (f, args) = slh_member.job_args(&me);
    n.mined("P5 register the slhdsa128s member, relayer mode", f, args).await;

    let mut list = vec![(FNDSA512, fk.ua, 1u16), (MLDSA65, ml.ua, 1), (SLHDSA128S, sl.ua, 1)];
    list.sort_by_key(|m| m.1);
    let kd = scaas_ua::encode_msig(3, &list);
    let ua = scaas_ua::ua_of(MSIG, &kd).unwrap();
    let d = register_digest(MSIG, &ua, &no_attrs(), &[0; 32]);
    let slots: Vec<MemberSig> = list.iter().enumerate().map(|(i, m)| {
        let msg = member_message(m.0, &ua, &ua8::pop_v2_tag(), &d);
        MemberSig { index: i as u16, members: vec![], sig: match m.0 { FNDSA512 => fk.sign(&msg), SLHDSA128S => sl.sign(&msg), _ => ml.sign(&msg) } }
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
    // one bit of the slhdsa128s slot: the same refusal, so the slot is checked, not skipped
    let at = list.iter().position(|m| m.0 == SLHDSA128S).unwrap();
    let mut bad = slots.clone();
    bad[at].sig[40] ^= 1;
    let (f, args) = Rec { pop: encode_member_sigs(&bad), ..rec.clone() }.job_args(&me);
    let (state, last, tx) = n.run(0, call_job(&n.registry, f, args)).await;
    println!("P5 flipped slhdsa128s slot: job {state}, reason {}", last["error"]);
    assert_eq!((state.as_str(), tx.is_none()), ("dead", true), "{last}");
    assert!(last["error"].as_str().unwrap_or_default().contains("UAPoP"), "{last}");
    // no relayer named: the chain cannot verify the slot
    let (f, args) = rec.job_args(&none);
    let (state, last, _) = n.run(0, call_job(&n.registry, f, args)).await;
    println!("P5 no relayer: job {state}, reason {}", last["error"]);
    assert_eq!(state, "dead", "{last}");

    let (f, args) = rec.job_args(&me);
    n.mined("P5 register_msig fndsa512 + mldsa65 + slhdsa128s slots, relayer mode", f, args).await;
    n.rec(&ua).await.eq("P5: Soroban against the arguments", &rec);
    let marks = n.checked_of(&ua).await;
    assert_eq!(marks[0], (2, Some(g(&key(0)))), "the record carries the lane's mark");

    // EVM verifies both slots: the signatures the node passed are the ones a chain accepts
    c.a.send("P5 register the fndsa512 member", member.calldata()).await;
    c.a.cache_key("P5 mldsa65 member", &ml.key).await;
    c.a.send("P5 register the mldsa65 member", ml_rec(&ml, &no_attrs(), &[0; 32], vec![]).calldata()).await;
    c.a.send("P5 register the slhdsa128s member", slh_member.calldata()).await;
    c.a.send("P5 registerMsig fndsa512 + mldsa65 + slhdsa128s slots", rec.calldata()).await;
    c.a.rec(&ua).await.eq("P5: EVM A against Soroban", &n.rec(&ua).await);
    println!("P5 result: an fndsa512 slot and an slhdsa128s slot signed, passed check_registration, stored marked Relayer on Soroban and verified by EVM; remaining without a positive on a host: group vk slice, BLS slot with pop = false");
}
