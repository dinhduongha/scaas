// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T41.soroban (with T29.soroban, T30.soroban; spec §27.5): a `G…` subject's ops through `/v1/ops` and by self-relay, the
//! hand-off and its import with every check in its order, the resend, the follow by chain facts and the native XLM send, against
//! a fake Soroban RPC and a fake gateway (`tests/common/fake_http.rs`, local only). The keys are the vectors' (the BIP-39 test
//! mnemonic of smartcontracts/vectors/families/soroban.json): the SDK's prepared pay is that file's row, byte for byte. Every
//! refusal beside its control. Builds without `evm`.
#![cfg(feature = "soroban")]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic
)]

#[path = "common/fake_http.rs"]
mod fake_http;

use fake_http::serve;
use scaas_sdk::vault::{ImportWords, MemoryStore};
use scaas_sdk::wallet::{
    NativeKeyRef, SignedOpBlob, SorobanImportExpect, SorobanNativeSend, SorobanOpKind,
    SorobanOpRequest, SorobanPath, Wallet,
};
use scaas_sdk::{
    ChainProfile, EndpointConfig, Family, FamilyParams, Finality, Limits, ListedToken, NativeCap,
    RuntimeChoice, Sdk, SdkConfig, SdkError,
};
use scaas_ua::wallet::SecretBytes;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

const PASSPHRASE: &str = "Standalone Network ; February 2017";
const PASS: &str = "river-otter-7 ünï";
const CHAIN: &str = "soroban-local";
const L: u64 = 5_000;
/// the vectors' pay: `valid_until` 1790000300 and expiry ledger 5720 at ledger 5000, so `now` is 720 s before it
const NOW: u64 = 1_790_000_300 - 720;

fn file(p: &str) -> Value {
    let p = format!(
        "{}/../../smartcontracts/vectors/{p}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}
fn fam() -> Value {
    file("families/soroban.json")
}
fn hexb(s: &str) -> Vec<u8> {
    let s = s.trim_start_matches("0x");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn b64(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(b)
}
fn unb64(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}
fn strkey_key(s: &str) -> [u8; 32] {
    let (mut out, mut acc, mut bits) = (vec![], 0u32, 0);
    for c in s.bytes() {
        let v = if c.is_ascii_uppercase() {
            c - b'A'
        } else {
            c - b'2' + 26
        };
        acc = (acc << 5) | u32::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out[1..33].try_into().unwrap()
}
fn account_key(g: &str) -> Vec<u8> {
    [&[0u8; 8][..], &strkey_key(g)].concat()
}
/// `LedgerEntryData::Account` of `g` with `balance` and `seq` (the fixed head, then empty fields, as clientkeys' `accountEntry`)
fn account_entry(g: &str, balance: i64, seq: i64) -> Vec<u8> {
    let mut v = account_key(g);
    v.extend_from_slice(&balance.to_be_bytes());
    v.extend_from_slice(&seq.to_be_bytes());
    v.extend_from_slice(&[0; 16]);
    v.extend_from_slice(&[1, 0, 0, 0]);
    v.extend_from_slice(&[0; 8]);
    v
}

/// The fake chain: accounts, entries present, the transactions it took and their status, the simulation's answer.
struct Node {
    ledger: u64,
    entries: HashMap<Vec<u8>, Vec<u8>>,
    /// every envelope simulated and sent
    simulated: Vec<Vec<u8>>,
    sent: Vec<Vec<u8>>,
    /// a sent transaction's status by its id: SUCCESS, FAILED, NOT_FOUND
    status: HashMap<String, &'static str>,
    /// the status a new transaction gets; the keys a SUCCESS spends
    next: &'static str,
    spends: Vec<Vec<u8>>,
    sim_error: Option<String>,
    fee_p90: &'static str,
    /// the simulation records the source account's own `SourceAccount` entry (a self-paid op), not the subject's Address one
    auth_source: bool,
}
type Fake = Arc<Mutex<Node>>;

/// The auth entry of the native rows' self-relay: its signer is the vectors' subject (what a simulation records).
fn recorded_auth() -> Vec<u8> {
    let n = file("native/soroban-tx.json");
    let r = &n["rows"][0];
    let (tx, data) = (
        hexb(r["tx"].as_str().unwrap()),
        hexb(r["dataXdr"].as_str().unwrap()),
    );
    let mut prefix = vec![0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
    prefix.extend_from_slice(&strkey_key(
        r["op"]["invoke"]["auth"][0]["from"].as_str().unwrap(),
    ));
    let at = tx
        .windows(prefix.len())
        .position(|w| w == prefix.as_slice())
        .unwrap();
    tx[at..tx.len() - data.len() - 4].to_vec()
}

/// A `SourceAccount` auth entry of the token's `pay` (what a simulation records for the transaction's own source).
fn source_auth() -> Vec<u8> {
    let mut e = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    e.extend_from_slice(&strkey_key(fam()["token"].as_str().unwrap()));
    e.extend_from_slice(&[0, 0, 0, 3, b'p', b'a', b'y', 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    e
}

fn answer(n: &mut Node, body: &[u8]) -> (u16, Vec<u8>) {
    let r: Value = serde_json::from_slice(body).unwrap();
    let nr = file("native/soroban-tx.json");
    let nid = hexb(nr["networkId"].as_str().unwrap());
    let result = match r["method"].as_str().unwrap() {
        "getNetwork" => json!({"passphrase": PASSPHRASE, "protocolVersion": 30}),
        "getLatestLedger" => {
            json!({"sequence": n.ledger, "id": "ab".repeat(32), "protocolVersion": 30})
        }
        "getFeeStats" => {
            json!({"sorobanInclusionFee": {"p90": n.fee_p90}, "inclusionFee": {"p90": "100"}})
        }
        "getLedgerEntries" => {
            let entries: Vec<Value> = r["params"]["keys"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|k| {
                    let key = unb64(k.as_str().unwrap());
                    n.entries
                        .get(&key)
                        .map(|x| json!({"key": k, "xdr": b64(x), "lastModifiedLedgerSeq": 1}))
                })
                .collect();
            json!({"entries": entries, "latestLedger": n.ledger})
        }
        "simulateTransaction" => {
            n.simulated
                .push(unb64(r["params"]["transaction"].as_str().unwrap()));
            match &n.sim_error {
                Some(e) => json!({"latestLedger": n.ledger, "error": e}),
                None => json!({
                    "latestLedger": n.ledger,
                    "minResourceFee": "1234567",
                    "transactionData": b64(&hexb(nr["rows"][0]["dataXdr"].as_str().unwrap())),
                    "results": [{"auth": [b64(&if n.auth_source { source_auth() } else { recorded_auth() })], "xdr": "AAAAAQ=="}],
                }),
            }
        }
        "sendTransaction" => {
            let env = unb64(r["params"]["transaction"].as_str().unwrap());
            let tx = &env[4..env.len() - 76];
            let id = hex(&scaas_ua::sha256(&[&nid[..], &[0, 0, 0, 2], tx].concat()));
            n.sent.push(env.clone());
            n.status.insert(id.clone(), n.next);
            if n.next == "SUCCESS" || n.next == "FAILED" {
                for k in std::mem::take(&mut n.spends) {
                    n.entries.insert(k, vec![0, 0, 0, 6]);
                }
            }
            json!({"status": "PENDING", "hash": id, "latestLedger": n.ledger})
        }
        "getTransaction" => {
            let h = r["params"]["hash"].as_str().unwrap();
            match n.status.get(h).copied().unwrap_or("NOT_FOUND") {
                "NOT_FOUND" => json!({"status": "NOT_FOUND", "latestLedger": n.ledger}),
                s => json!({"status": s, "ledger": n.ledger, "latestLedger": n.ledger}),
            }
        }
        m => panic!("{m}"),
    };
    (
        200,
        serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": r["id"], "result": result})).unwrap(),
    )
}

type Bodies = Arc<Mutex<Vec<Value>>>;

struct T {
    #[allow(dead_code)]
    sdk: Arc<Sdk>,
    w: Arc<Wallet>,
    seed: String,
    node: Fake,
    gateway: Bodies,
    clock: Arc<AtomicU64>,
}

fn key(t: &T, index: u32) -> NativeKeyRef {
    NativeKeyRef {
        seed: t.seed.clone(),
        network: "stellar".into(),
        index,
        change: None,
        coin_type: None,
        path: None,
    }
}
fn g(i: usize) -> String {
    let v = fam();
    match i {
        0 => v["ops"][0]["shown"]["from"].as_str().unwrap().into(),
        1 => v["ops"][0]["shown"]["to"].as_str().unwrap().into(),
        _ => file("native/soroban-tx.json")["payer"]
            .as_str()
            .unwrap()
            .into(),
    }
}

fn endpoint(url: &str) -> EndpointConfig {
    EndpointConfig {
        url: url.into(),
        class: scaas_rpc::Class::Named,
        label: None,
        auth: None,
    }
}

async fn setup(cap: Option<&str>, policy: scaas_rpc::Policy, extra_rpc: Option<Fake>) -> T {
    let v = fam();
    let mut entries = HashMap::new();
    for (i, seq) in [(0, 7i64), (1, 9), (2, 41)] {
        entries.insert(account_key(&g(i)), account_entry(&g(i), 100_000_000, seq));
    }
    let node = Arc::new(Mutex::new(Node {
        ledger: L,
        entries,
        simulated: vec![],
        sent: vec![],
        status: HashMap::new(),
        next: "SUCCESS",
        spends: vec![],
        sim_error: None,
        fee_p90: "100",
        auth_source: false,
    }));
    let up = |f: Fake| async move {
        serve(Arc::new(move |_m: &str, _p: &str, b: &[u8]| {
            answer(&mut f.lock().unwrap(), b)
        }))
        .await
        .0
    };
    let mut rpc = vec![endpoint(&up(node.clone()).await)];
    if let Some(e) = extra_rpc {
        rpc.push(endpoint(&up(e).await));
    }
    let bodies: Bodies = Arc::default();
    let b2 = bodies.clone();
    let (gw, _) = serve(Arc::new(move |_m: &str, p: &str, body: &[u8]| {
        assert_eq!(p, "/v1/ops");
        b2.lock()
            .unwrap()
            .push(serde_json::from_slice(body).unwrap());
        (202, br#"{"status":"queued","intent_id":"0x01"}"#.to_vec())
    }))
    .await;
    let profile = ChainProfile {
        key: CHAIN.into(),
        family: Family::Soroban,
        chain_id: None,
        chain_uid: format!("0x{}", hex(&scaas_ua::sha256(PASSPHRASE.as_bytes()))),
        rpc,
        rpc_policy: policy,
        gateways: vec![endpoint(&gw)],
        registry: None,
        factory: None,
        router: None,
        finality: Finality::Finalized,
        tx_gas_cap: None,
        gas: Default::default(),
        max_valid_secs: None,
        verifiers: vec![],
        verifier_policy: scaas_rpc::Policy::Failover,
        gas_opt_in: vec![],
        dexes: vec![],
        wrappers: vec![],
        tokens: vec![ListedToken {
            address: v["token"].as_str().unwrap().into(),
            symbol: "USDC".into(),
            decimals: 7,
        }],
        l1_fee: None,
        disabled_kinds: vec![],
        family_params: Some(FamilyParams::Soroban {
            passphrase: PASSPHRASE.into(),
            xlm_sac: v["sac"].as_str().unwrap().into(),
        }),
    };
    let clock = Arc::new(AtomicU64::new(NOW));
    let c2 = clock.clone();
    let sdk = Sdk::open(SdkConfig {
        profiles: vec![profile],
        store: MemoryStore::new(),
        authenticator: None,
        rp_id: None,
        runtime: RuntimeChoice::Adopt(tokio::runtime::Handle::current()),
        limits: Limits {
            max_native_cost: cap
                .map(|m| {
                    vec![NativeCap {
                        chain: CHAIN.into(),
                        max: m.into(),
                    }]
                })
                .unwrap_or_default(),
            ..Limits::default()
        },
        clock: Some(Arc::new(move || c2.load(SeqCst))),
        gas_tables: vec![],
    })
    .await
    .unwrap();
    let sec = |b: &[u8]| Arc::new(SecretBytes::from_zeroizing(Zeroizing::new(b.to_vec())).unwrap());
    let seed = sdk
        .vault()
        .import_words(ImportWords {
            label: "main".into(),
            words: sec(v["mnemonic"].as_str().unwrap().as_bytes()),
            vault_passphrase: sec(PASS.as_bytes()),
        })
        .await
        .unwrap()
        .id;
    let w = sdk.wallet();
    T {
        sdk,
        w,
        seed,
        node,
        gateway: bodies,
        clock,
    }
}

fn pay_row() -> Value {
    fam()["ops"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["kind"] == "pay")
        .unwrap()
        .clone()
}

fn pay(t: &T) -> SorobanOpRequest {
    let f = &pay_row()["terms"]["fields"];
    SorobanOpRequest {
        chain: CHAIN.into(),
        subject: key(t, 0),
        contract: fam()["token"].as_str().unwrap().into(),
        kind: SorobanOpKind::Pay {
            to: f["to"].as_str().unwrap().into(),
            amount: f["amount"].as_str().unwrap().into(),
            pay_ref: f["pay_ref"].as_str().unwrap().into(),
        },
        valid_until: f["valid_until"].as_u64().unwrap(),
    }
}

fn code<T>(r: Result<T, SdkError>) -> &'static str {
    r.map_or_else(|e| e.code(), |_| "Ok")
}

/// The keys a landed pay spends: its nonce and its `pay_ref` (the native rows' footprint names both).
fn pay_spends() -> Vec<Vec<u8>> {
    let n = file("native/soroban-tx.json");
    let rw = n["rows"][0]["op"]["invoke"]["data"]["readWrite"]
        .as_array()
        .unwrap();
    vec![
        unb64(rw[2].as_str().unwrap()),
        unb64(rw[3].as_str().unwrap()),
    ]
}

/// The positive control of T29: the SDK's prepared pay is the vectors' row (its nonce, its expiry), and the gateway receives the
/// row's `signed_op`, signed once, as `POST /v1/ops {chain, op}`; the row is written ahead and `sent`.
#[tokio::test(flavor = "multi_thread")]
async fn a_pay_through_the_gateways_is_the_vectors_signed_op() {
    let t = setup(None, scaas_rpc::Policy::Failover, None).await;
    let row = pay_row();
    let p = t.w.soroban_prepare(pay(&t)).await.unwrap();
    assert_eq!(p.nonce, row["terms"]["nonce"].as_str().unwrap());
    assert_eq!(
        u64::from(p.expiry),
        row["terms"]["expiry"].as_u64().unwrap()
    );
    assert!(!p.relayer_bound, "Soroban binds no submitter");
    let q =
        t.w.soroban_quote(p.clone(), SorobanPath::Gateway)
            .await
            .unwrap();
    assert_eq!((q.gateways.clone(), q.native.clone()), (vec![0], None));
    let id = t.w.soroban_submit(p, q).await.unwrap();
    let b = t.gateway.lock().unwrap().clone();
    assert_eq!(b.len(), 1);
    assert_eq!(b[0], json!({"chain": CHAIN, "op": row["signed_op"]}));
    // queued is no landing: the row ends on the chain's fact, the op's spent entries
    assert_eq!(t.w.soroban_follow(id.clone()).await.unwrap(), "sent");
    for k in pay_spends() {
        t.node.lock().unwrap().entries.insert(k, vec![0, 0, 0, 6]);
    }
    assert_eq!(t.w.soroban_follow(id).await.unwrap(), "landed");
}

#[tokio::test(flavor = "multi_thread")]
async fn prepare_refusals_beside_their_control() {
    let t = setup(None, scaas_rpc::Policy::Failover, None).await;
    assert_eq!(code(t.w.soroban_prepare(pay(&t)).await), "Ok", "control");
    let mut r = pay(&t);
    r.contract = fam()["sac"].as_str().unwrap().into();
    assert_eq!(
        code(t.w.soroban_prepare(r).await),
        "ProfileMismatch",
        "an unlisted token"
    );
    let mut r = pay(&t);
    r.valid_until = NOW;
    assert_eq!(code(t.w.soroban_prepare(r).await), "ValidUntilRefused");
    let mut r = pay(&t);
    r.valid_until = NOW + 86_401;
    assert_eq!(code(t.w.soroban_prepare(r).await), "ValidUntilRefused");
    let mut r = pay(&t);
    r.kind = SorobanOpKind::Transfer {
        to: g(1),
        amount: "0".into(),
    };
    assert_eq!(
        code(t.w.soroban_prepare(r).await),
        "Argument",
        "an amount of 0"
    );
    let mut r = pay(&t);
    r.subject.network = "solana".into();
    assert_eq!(
        code(t.w.soroban_prepare(r).await),
        "Argument",
        "a subject that is no stellar key"
    );
}

/// T41's own-op self-relay: the quote simulates the unsigned op (record mode: no auth entry, no signature at quote time) from the
/// payer at its sequence + 1, prices it with the margin under the cap; submit simulates the signed entry and broadcasts the
/// payer's transaction. Above the cap, or no cap, `FeeAboveCap`.
#[tokio::test(flavor = "multi_thread")]
async fn an_own_op_self_relays_under_the_cap() {
    let resource = 1_234_567u64;
    let fee = 100 + resource + resource * 15 / 100;
    for (cap, want) in [
        (None, "FeeAboveCap"),
        (Some((fee - 1).to_string()), "FeeAboveCap"),
        (Some(fee.to_string()), "Ok"),
    ] {
        let t = setup(cap.as_deref(), scaas_rpc::Policy::Failover, None).await;
        let p = t.w.soroban_prepare(pay(&t)).await.unwrap();
        let q =
            t.w.soroban_quote(p, SorobanPath::SelfRelay { payer: key(&t, 2) })
                .await;
        let q = match q {
            Err(e) => {
                assert_eq!(e.code(), want, "{cap:?}");
                continue;
            }
            Ok(q) => q,
        };
        assert_eq!(want, "Ok", "{cap:?}");
        assert_eq!(q.seq.as_deref(), Some("42"), "the payer's sequence + 1");
        assert_eq!(q.payer.as_deref(), Some(g(2).as_str()));
        let n = q.native.clone().unwrap();
        assert_eq!(
            (n.fee.as_str(), n.max_cost.as_str()),
            (fee.to_string().as_str(), fee.to_string().as_str())
        );
        // the quote's simulation carried no auth entry: the record mode
        let sim = t.node.lock().unwrap().simulated[0].clone();
        assert!(
            !sim.windows(12)
                .any(|w| w == [0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0]),
            "no auth entry at quote time"
        );
        t.node.lock().unwrap().spends = pay_spends();
        let p = t.w.soroban_prepare(pay(&t)).await.unwrap();
        let id = t.w.soroban_submit(p, q).await.unwrap();
        let (sent, sims) = {
            let n = t.node.lock().unwrap();
            (n.sent.clone(), n.simulated.clone())
        };
        assert_eq!(sent.len(), 1);
        let env = &sent[0];
        // the source is the payer, its sequence the quote's, its fee the quoted one; the subject's signed entry inside
        assert_eq!(&env[8..40], &strkey_key(&g(2)));
        assert_eq!(&env[40..44], &(fee as u32).to_be_bytes());
        assert_eq!(&env[44..52], &42i64.to_be_bytes());
        let sig = hexb(pay_row()["signature"].as_str().unwrap());
        assert!(
            env.windows(64).any(|w| w == sig.as_slice()),
            "the subject's signature of the vectors' row"
        );
        assert!(
            sims.last()
                .unwrap()
                .windows(64)
                .any(|w| w == sig.as_slice()),
            "submit simulated the signed entry"
        );
        assert_eq!(t.w.soroban_follow(id).await.unwrap(), "landed");
    }
}

/// The hand-off: A signs and hands off (nothing sent), B imports with every check in its order, each refusal beside the control,
/// quotes from its own payer (the enforcing simulation of A's entry) and submits. A's row ends `landed` on the chain facts.
#[tokio::test(flavor = "multi_thread")]
async fn a_handed_off_pay_imports_with_each_check_and_lands() {
    let t = setup(Some("100000000"), scaas_rpc::Policy::Failover, None).await;
    let p = t.w.soroban_prepare(pay(&t)).await.unwrap();
    let h = t.w.soroban_hand_off(p).await.unwrap();
    let blob = h.blob.clone();
    assert!(
        t.node.lock().unwrap().sent.is_empty() && t.gateway.lock().unwrap().is_empty(),
        "nothing sent"
    );
    assert_eq!(
        t.w.soroban_follow(h.op.clone()).await.unwrap(),
        "handed_off",
        "unspent: the signer's row waits"
    );
    assert_eq!(blob.signature.as_str(), pay_row()["signature"].as_str());
    let me = SorobanImportExpect {
        chain: CHAIN.into(),
        payee: vec![g(1)],
    };
    let import = |b: SignedOpBlob, e: SorobanImportExpect| {
        let w = t.w.clone();
        async move { code(w.soroban_import(b, e).await) }
    };
    assert_eq!(import(blob.clone(), me.clone()).await, "Ok", "control");
    let json = blob.to_json().unwrap();
    assert_eq!(SignedOpBlob::from_json(&json).unwrap(), blob);
    // the bounds and the unknown field
    let mut v: Value = serde_json::from_str(&json).unwrap();
    v["footprint"] = json!(["AAAA"]);
    assert_eq!(
        code(SignedOpBlob::from_json(&v.to_string())),
        "Argument",
        "no footprint from the blob"
    );
    let mut v: Value = serde_json::from_str(&json).unwrap();
    v["message"]["invocation"]["sub_invocations"] = json!([[[[[[[[1]]]]]]]]);
    assert_eq!(
        code(SignedOpBlob::from_json(&v.to_string())),
        "Argument",
        "too deep"
    );
    let big = format!(
        r#"{},"pad":"{}"}}"#,
        &json[..json.len() - 1],
        "x".repeat(256 << 10)
    );
    assert_eq!(
        code(SignedOpBlob::from_json(&big)),
        "Argument",
        "above 256 KiB"
    );
    // each check in its order
    let mut b = blob.clone();
    b.chain_uid = format!("0x{}", "11".repeat(32));
    assert_eq!(import(b, me.clone()).await, "ProfileMismatch");
    let mut b = blob.clone();
    b.contract = fam()["sac"].as_str().unwrap().into();
    b.message["invocation"]["contract"] = json!(b.contract);
    assert_eq!(
        import(b, me.clone()).await,
        "ProfileMismatch",
        "an unlisted contract"
    );
    let mut b = blob.clone();
    b.entry = "approve".into();
    b.message["invocation"]["function"] = json!("approve");
    assert_eq!(import(b, me.clone()).await, "ImportKindRefused");
    assert_eq!(
        import(
            blob.clone(),
            SorobanImportExpect {
                chain: CHAIN.into(),
                payee: vec![g(2)]
            }
        )
        .await,
        "ImportNotPayee"
    );
    let mut b = blob.clone();
    b.message["expiry"] = json!(L + 119);
    assert_eq!(import(b, me.clone()).await, "ImportExpired");
    t.clock.store(1_790_000_300 - 119, SeqCst);
    assert_eq!(
        import(blob.clone(), me.clone()).await,
        "ImportExpired",
        "the pay's valid_until"
    );
    t.clock.store(NOW, SeqCst);
    // the importer's simulation refuses: ImportedOpRefused; then the control quotes from B's payer
    let imported = t.w.soroban_import(blob.clone(), me.clone()).await.unwrap();
    assert!(imported.subject.is_none() && imported.signature.is_some());
    t.node.lock().unwrap().sim_error = Some("HostError: Error(Auth, InvalidAction)".into());
    let path = SorobanPath::SelfRelay { payer: key(&t, 1) };
    assert_eq!(
        code(t.w.soroban_quote(imported.clone(), path.clone()).await),
        "ImportedOpRefused"
    );
    t.node.lock().unwrap().sim_error = None;
    let q = t.w.soroban_quote(imported.clone(), path).await.unwrap();
    assert_eq!(q.seq.as_deref(), Some("10"));
    t.node.lock().unwrap().spends = pay_spends();
    let id = t.w.soroban_submit(imported, q).await.unwrap();
    assert_eq!(t.w.soroban_follow(id).await.unwrap(), "landed");
    // the same blob again is consumed; the signer's own row ends on the chain facts
    assert_eq!(import(blob, me).await, "ImportConsumed");
    assert_eq!(
        t.w.soroban_follow(h.op).await.unwrap(),
        "landed",
        "the signer's row on the chain facts"
    );
}

/// An unbound pay landed by another account first: the payee's own transaction fails, and its row is `consumed`, never failed.
#[tokio::test(flavor = "multi_thread")]
async fn a_pay_landed_by_another_first_is_consumed_for_the_payee() {
    let t = setup(Some("100000000"), scaas_rpc::Policy::Failover, None).await;
    let p = t.w.soroban_prepare(pay(&t)).await.unwrap();
    let blob = t.w.soroban_hand_off(p).await.unwrap().blob;
    let me = SorobanImportExpect {
        chain: CHAIN.into(),
        payee: vec![g(1)],
    };
    let imported = t.w.soroban_import(blob, me).await.unwrap();
    let path = SorobanPath::SelfRelay { payer: key(&t, 1) };
    let q = t.w.soroban_quote(imported.clone(), path).await.unwrap();
    {
        let mut n = t.node.lock().unwrap();
        n.next = "FAILED";
        n.spends = pay_spends();
    }
    let id = t.w.soroban_submit(imported, q).await.unwrap();
    assert_eq!(t.w.soroban_follow(id.clone()).await.unwrap(), "consumed");
    assert_eq!(
        t.w.soroban_follow(id).await.unwrap(),
        "consumed",
        "terminal"
    );
}

/// A self-relay whose transaction expired unlanded stays `sent` (the op may still land); `resend` gives the same signed op for a
/// new transaction around it, at the payer's new sequence, never signed again; then it lands.
#[tokio::test(flavor = "multi_thread")]
async fn resend_wraps_the_same_signed_op_in_a_new_transaction() {
    let t = setup(Some("100000000"), scaas_rpc::Policy::Failover, None).await;
    let p = t.w.soroban_prepare(pay(&t)).await.unwrap();
    let q =
        t.w.soroban_quote(p.clone(), SorobanPath::SelfRelay { payer: key(&t, 2) })
            .await
            .unwrap();
    t.node.lock().unwrap().next = "FAILED";
    let id = t.w.soroban_submit(p.clone(), q).await.unwrap();
    // the payer's transaction failed and the op is unspent: still `sent`, never failed
    assert_eq!(t.w.soroban_follow(id.clone()).await.unwrap(), "sent");
    let r = t.w.soroban_resend(id.clone()).await.unwrap();
    assert_eq!(
        (r.nonce.as_str(), r.expiry, r.op.as_deref()),
        (p.nonce.as_str(), p.expiry, Some(id.as_str()))
    );
    assert_eq!(
        r.signature.as_deref(),
        Some(pay_row()["signature"].as_str().unwrap())
    );
    // the payer's sequence moved on (its other transaction landed)
    t.node
        .lock()
        .unwrap()
        .entries
        .insert(account_key(&g(2)), account_entry(&g(2), 100_000_000, 42));
    let q2 =
        t.w.soroban_quote(r.clone(), SorobanPath::SelfRelay { payer: key(&t, 2) })
            .await
            .unwrap();
    assert_eq!(q2.seq.as_deref(), Some("43"));
    {
        let mut n = t.node.lock().unwrap();
        n.next = "SUCCESS";
        n.spends = pay_spends();
    }
    assert_eq!(t.w.soroban_submit(r, q2).await.unwrap(), id, "the same row");
    let sent = t.node.lock().unwrap().sent.clone();
    assert_eq!(sent.len(), 2);
    let sig = hexb(pay_row()["signature"].as_str().unwrap());
    assert!(
        sent.iter()
            .all(|e| e.windows(64).any(|w| w == sig.as_slice())),
        "one signature of the op in both"
    );
    assert_ne!(sent[0], sent[1]);
    assert_eq!(t.w.soroban_follow(id).await.unwrap(), "landed");
}

/// The Native column: a `Payment` of XLM from the payer's sequence + 1 at the inclusion fee under the cap, signed once, sent,
/// followed to its ledger; a destination with no account, an amount of 0, no cap: refused before anything is signed.
#[tokio::test(flavor = "multi_thread")]
async fn a_native_xlm_send() {
    let t = setup(Some("100"), scaas_rpc::Policy::Failover, None).await;
    let send = |to: &str, amount: &str| SorobanNativeSend {
        chain: CHAIN.into(),
        key: key(&t, 2),
        to: to.into(),
        amount: amount.into(),
    };
    let q =
        t.w.soroban_prepare_native_send(send(&g(1), "25000000"))
            .await
            .unwrap();
    assert_eq!(
        (q.seq.as_str(), q.fee, q.from.as_str()),
        ("42", 100, g(2).as_str())
    );
    let id = t.w.soroban_submit_native_send(q).await.unwrap();
    let env = t.node.lock().unwrap().sent[0].clone();
    assert_eq!(&env[44..52], &42i64.to_be_bytes(), "the sequence advanced");
    assert!(
        env.windows(32).any(|w| w == strkey_key(&g(1))),
        "to the payee"
    );
    assert_eq!(t.w.soroban_follow(id).await.unwrap(), "landed");
    let fresh = {
        let v = fam();
        v["holders"]["account"].as_str().unwrap().to_string()
    };
    assert_eq!(
        code(t.w.soroban_prepare_native_send(send(&fresh, "1")).await),
        "Argument",
        "no account there"
    );
    assert_eq!(
        code(t.w.soroban_prepare_native_send(send(&g(1), "0")).await),
        "Argument"
    );
    assert_eq!(
        code(t.w.soroban_prepare_native_send(send(&g(1), "01")).await),
        "Argument"
    );
    let t = setup(None, scaas_rpc::Policy::Failover, None).await;
    let send = SorobanNativeSend {
        chain: CHAIN.into(),
        key: key(&t, 2),
        to: g(1),
        amount: "1".into(),
    };
    assert_eq!(
        code(t.w.soroban_prepare_native_send(send).await),
        "FeeAboveCap",
        "no cap"
    );
}

/// ARCH-POS-15 under `strict_majority`: a second endpoint whose fee statistics differ leaves no majority; the same answers pass.
#[tokio::test(flavor = "multi_thread")]
async fn strict_majority_compares_the_quotes_reads() {
    for (p90, want) in [("100", "Ok"), ("999", "EndpointNoMajority")] {
        let other = Arc::new(Mutex::new(Node {
            ledger: L,
            entries: HashMap::new(),
            simulated: vec![],
            sent: vec![],
            status: HashMap::new(),
            next: "SUCCESS",
            spends: vec![],
            sim_error: None,
            fee_p90: p90,
            auth_source: false,
        }));
        for i in 0..3 {
            other.lock().unwrap().entries.insert(
                account_key(&g(i)),
                account_entry(&g(i), 100_000_000, [7, 9, 41][i]),
            );
        }
        let t = setup(
            Some("100000000"),
            scaas_rpc::Policy::StrictMajority,
            Some(other),
        )
        .await;
        let p = t.w.soroban_prepare(pay(&t)).await.unwrap();
        let q =
            t.w.soroban_quote(p, SorobanPath::SelfRelay { payer: key(&t, 2) })
                .await;
        assert_eq!(code(q), want);
    }
}

/// Owner 2026-11-22 ("accept SourceAccount when self-paying"): a pay self-relayed by its own subject (the transaction's
/// source is A) is simulated with A's `SourceAccount` entry, accepted, and lands; the same entry when another key pays
/// (the source is not the subject) is refused before anything is signed.
#[tokio::test(flavor = "multi_thread")]
async fn a_source_account_entry_only_when_the_subject_pays() {
    let t = setup(Some("100000000"), scaas_rpc::Policy::Failover, None).await;
    t.node.lock().unwrap().auth_source = true;
    let p = t.w.soroban_prepare(pay(&t)).await.unwrap();
    let other =
        t.w.soroban_quote(p.clone(), SorobanPath::SelfRelay { payer: key(&t, 2) })
            .await;
    assert_eq!(
        code(other),
        "Revert",
        "another payer: the call needs a signer other than its source"
    );
    let q =
        t.w.soroban_quote(p.clone(), SorobanPath::SelfRelay { payer: key(&t, 0) })
            .await
            .unwrap();
    assert_eq!(
        q.payer.as_deref(),
        Some(g(0).as_str()),
        "A pays its own transaction"
    );
    assert_eq!(q.seq.as_deref(), Some("8"), "A's sequence + 1");
    t.node.lock().unwrap().spends = pay_spends();
    let id = t.w.soroban_submit(p, q).await.unwrap();
    let env = t.node.lock().unwrap().sent[0].clone();
    assert_eq!(&env[8..40], &strkey_key(&g(0)), "the source is the subject");
    assert_eq!(t.w.soroban_follow(id).await.unwrap(), "landed");
}
