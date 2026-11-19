// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T9: `account` rows, UA ids, restore (spec §7, CLI-SDK-07), each refusal with its control. The restore scan and the
//! delegation mark read fake JSON-RPC endpoints on 127.0.0.1:0 (local only).
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use scaas_sdk::account::{AddNative, AddUa, AddWatch, Restore};
use scaas_sdk::vault::{ImportWords, MemoryStore, SecureStore, Unlock};
use scaas_sdk::{
    ChainProfile, EndpointConfig, Family, Finality, Limits, RuntimeChoice, Sdk, SdkConfig, SdkError,
};
use scaas_ua::wallet::{SecretBytes, Wallet};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

const PASS: &str = "river-otter-7 ünï";
/// `ua/keys.json`'s `pq_kat` mnemonic.
const REPO: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";
const REGISTRY: &str = "0x5ca00000000000000000000000000000000000a1";
const CHAIN_ID: u64 = 31337;

fn sec(s: &str) -> Arc<SecretBytes> {
    Arc::new(SecretBytes::from_zeroizing(Zeroizing::new(s.as_bytes().to_vec())).unwrap())
}

fn code<T>(r: Result<T, SdkError>) -> &'static str {
    r.map_or_else(|e| e.code(), |_| "Ok")
}

fn load(p: &str) -> Value {
    let path = format!(
        "{}/../../smartcontracts/vectors/{p}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn profile(urls: &[String]) -> ChainProfile {
    ChainProfile {
        key: "local-testnet".into(),
        family: Family::Evm,
        chain_id: Some(CHAIN_ID),
        chain_uid: format!("0x{}", "60".repeat(32)),
        rpc: urls
            .iter()
            .map(|u| EndpointConfig {
                url: u.clone(),
                class: scaas_rpc::Class::Named,
                label: None,
                auth: None,
            })
            .collect(),
        rpc_policy: scaas_rpc::Policy::Failover,
        gateways: vec![],
        registry: Some(REGISTRY.into()),
        factory: None,
        router: None,
        finality: Finality::Finalized,
        tx_gas_cap: None,
        gas: vec![],
        max_valid_secs: None,
        gas_opt_in: vec![],
        tokens: vec![],
    }
}

async fn open(store: Arc<dyn SecureStore>, urls: &[String]) -> Arc<Sdk> {
    let profiles = if urls.is_empty() {
        vec![]
    } else {
        vec![profile(urls)]
    };
    Sdk::open(SdkConfig {
        profiles,
        store,
        authenticator: None,
        rp_id: None,
        runtime: RuntimeChoice::Adopt(tokio::runtime::Handle::current()),
        limits: Limits::default(),
        clock: None,
        gas_tables: vec![],
    })
    .await
    .unwrap()
}

async fn with_seed(urls: &[String]) -> (Arc<Sdk>, Arc<MemoryStore>, String) {
    let m = MemoryStore::new();
    let s = open(m.clone(), urls).await;
    let req = ImportWords {
        label: "main".into(),
        words: sec(REPO),
        vault_passphrase: sec(PASS),
    };
    let id = s.vault().import_words(req).await.unwrap().id;
    (s, m, id)
}

fn ua_req(seed: &str, kind: u16, account: u32, index: u32) -> AddUa {
    AddUa {
        seed: seed.into(),
        kind,
        account,
        index,
        name: format!("k{kind} a{account} i{index}"),
    }
}

// --- a fake JSON-RPC endpoint (HTTP/1.1, keep-alive), chain 31337 ---

struct Fake {
    registered: HashSet<String>,
    /// a registered UA answered as one byte `0x01` instead of an ABI `bool` word
    short: std::sync::atomic::AtomicBool,
    code: Vec<(String, String)>,
    calls: AtomicUsize,
}

fn block(number: u64) -> Value {
    let z = format!("0x{}", "00".repeat(32));
    let hash = if number == 0 {
        format!("0x{}", "60".repeat(32))
    } else {
        format!("0x{}", "70".repeat(32))
    };
    json!({"timestamp": "0x6ac07487", "difficulty": "0x0", "extraData": "0x", "gasLimit": "0x1c9c380", "baseFeePerGas": "0x7",
        "gasUsed": "0x0", "logsBloom": format!("0x{}", "00".repeat(256)), "miner": format!("0x{}", "00".repeat(20)),
        "mixHash": z, "nonce": "0x0000000000000000", "receiptsRoot": z, "sha3Uncles": z, "size": "0x200", "stateRoot": z,
        "totalDifficulty": "0x0", "transactions": [], "transactionsRoot": z, "uncles": [], "number": format!("{number:#x}"),
        "hash": hash, "parentHash": format!("0x{}", "11".repeat(32))})
}

fn answer(f: &Fake, r: &Value) -> Value {
    let result = match r["method"].as_str().unwrap_or_default() {
        "eth_chainId" => json!(format!("{CHAIN_ID:#x}")),
        "eth_blockNumber" => json!("0x10"),
        "eth_getBlockByNumber" => block(if r["params"][0] == "0x0" { 0 } else { 16 }),
        "eth_call" => {
            f.calls.fetch_add(1, SeqCst);
            let data = r["params"][0]["input"]
                .as_str()
                .or(r["params"][0]["data"].as_str())
                .unwrap_or_default()
                .to_string();
            let ua = format!("0x{}", &data[10..]);
            if f.short.load(SeqCst) {
                json!(format!("0x{:02x}", u8::from(f.registered.contains(&ua))))
            } else {
                json!(format!("0x{:064x}", u8::from(f.registered.contains(&ua))))
            }
        }
        "eth_getCode" => {
            let who = r["params"][0]
                .as_str()
                .unwrap_or_default()
                .to_ascii_lowercase();
            json!(f
                .code
                .iter()
                .find(|(a, _)| *a == who)
                .map_or("0x".to_string(), |(_, c)| c.clone()))
        }
        _ => {
            return json!({"jsonrpc": "2.0", "id": r["id"], "error": {"code": -32601, "message": "no such method"}})
        }
    };
    json!({"jsonrpc": "2.0", "id": r["id"], "result": result})
}

async fn serve(f: Arc<Fake>) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move {
        while let Ok((mut c, _)) = l.accept().await {
            let f = f.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                loop {
                    let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
                        let mut chunk = [0u8; 4096];
                        match c.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                        continue;
                    };
                    let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
                    let len: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .map_or(0, |v| v.trim().parse().unwrap());
                    while buf.len() < end + 4 + len {
                        let mut chunk = [0u8; 4096];
                        match c.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let req: Value = serde_json::from_slice(&buf[end + 4..end + 4 + len]).unwrap();
                    buf.drain(..end + 4 + len);
                    let out = match &req {
                        Value::Array(a) => Value::Array(a.iter().map(|r| answer(&f, r)).collect()),
                        r => answer(&f, r),
                    };
                    let body = serde_json::to_vec(&out).unwrap();
                    let resp = format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", body.len());
                    if c.write_all(resp.as_bytes()).await.is_err()
                        || c.write_all(&body).await.is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    url
}

fn fake(registered: &[String], code: &[(String, String)]) -> Arc<Fake> {
    Arc::new(Fake {
        registered: registered.iter().cloned().collect(),
        code: code.to_vec(),
        calls: AtomicUsize::new(0),
        short: Default::default(),
    })
}

fn ua_at(kind: u16, account: u32, index: u32) -> String {
    let w = Wallet::from_mnemonic(REPO, "").unwrap();
    format!(
        "0x{}",
        hex(&w.ua_key(kind, account, index).unwrap().ua().unwrap())
    )
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// --- the tests ---

#[tokio::test(flavor = "multi_thread")]
async fn add_ua_row_names_its_seed() {
    let (s, m, seed) = with_seed(&[]).await;
    let row = s
        .account()
        .add_ua(ua_req(&seed, 0x0101, 0, 0))
        .await
        .unwrap();
    let want = load("ua/keys.json")["ua"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| {
            r["mnemonic"] == "pq_kat" && r["kind"] == 257 && r["account"] == 0 && r["index"] == 0
        })
        .unwrap()["ua"]
        .clone();
    assert_eq!(json!(row.id_text), want, "the UA of keys.json's row");
    assert_eq!(
        row.id_text,
        ua_at(0x0101, 0, 0),
        "and scaas-ua's derivation"
    );
    assert_eq!(
        (
            row.seed.as_str(),
            row.shape.as_str(),
            row.kind,
            row.account,
            row.index
        ),
        (seed.as_str(), "ua", Some(0x0101), Some(0), Some(0))
    );
    let rows = s.account().accounts(seed.clone()).await.unwrap();
    assert_eq!(rows, vec![row.clone()]);
    // the MAC was rewritten: another SDK over the same store unlocks (the MAC is checked at unlock) and lists the row verified
    let s2 = open(m.clone(), &[]).await;
    let before = s2.account().accounts(seed.clone()).await.unwrap();
    assert!(!before[0].verified, "a locked seed's rows are unverified");
    s2.vault()
        .unlock(seed.clone(), Unlock::Passphrase(sec(PASS)))
        .await
        .unwrap();
    assert!(s2.account().accounts(seed.clone()).await.unwrap()[0].verified);
    // control: the seed locked, nothing is added
    s.vault().lock(seed.clone()).await;
    assert_eq!(
        code(s.account().add_ua(ua_req(&seed, 0x0101, 0, 1)).await),
        "WalletLocked"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn one_index_per_wallet() {
    let (s, _m, seed) = with_seed(&[]).await;
    let a = s.account();
    assert_eq!(
        a.next_account(seed.clone()).await.unwrap(),
        0,
        "a seed without wallets"
    );
    a.add_ua(ua_req(&seed, 0x0101, 0, 0)).await.unwrap();
    a.add_ua(ua_req(&seed, 0x0103, 0, 0)).await.unwrap();
    assert_eq!(
        a.next_account(seed.clone()).await.unwrap(),
        1,
        "the second wallet takes account 1, never account 0 again"
    );
    let second = a.add_ua(ua_req(&seed, 0x0101, 1, 0)).await.unwrap();
    assert_ne!(second.id_text, ua_at(0x0101, 0, 0));
    assert_eq!(a.next_account(seed.clone()).await.unwrap(), 2);
    assert_eq!(
        code(a.add_ua(ua_req(&seed, 0x0101, 0, 0)).await),
        "AccountExists",
        "the same key twice (owner 2026-11-18, Q1)"
    );
    assert_eq!(a.accounts(seed).await.unwrap().len(), 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn eip2333_kinds_index_0_only() {
    let (s, _m, seed) = with_seed(&[]).await;
    let a = s.account();
    for kind in [0x0104u16, 0x0105, 0x0106, 0x0107] {
        assert_eq!(
            code(a.add_ua(ua_req(&seed, kind, 0, 1)).await),
            "Argument",
            "{kind:#06x} at index 1"
        );
    }
    let r = a.add_ua(ua_req(&seed, 0x0105, 0, 0)).await.unwrap();
    assert_eq!(r.id_text, ua_at(0x0105, 0, 0), "control: index 0");
    assert_eq!(
        code(a.add_ua(ua_req(&seed, 0x0101, 0, 1)).await),
        "Ok",
        "control: index 1 of a BIP-32 kind"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn restore_gap_scan() {
    let reg: Vec<String> = [0u32, 1, 5, 30]
        .iter()
        .map(|i| ua_at(0x0101, 0, *i))
        .collect();
    let f = fake(&reg, &[]);
    let url = serve(f.clone()).await;
    let (s, _m, seed) = with_seed(&[url]).await;
    let req = Restore {
        seed: seed.clone(),
        chain: "local-testnet".into(),
        kinds: vec![0x0101],
        account: 0,
        gap: 20,
    };
    let found = s.account().restore(req.clone()).await.unwrap();
    let idx: Vec<Option<u32>> = found.iter().map(|r| r.index).collect();
    assert_eq!(
        idx,
        vec![Some(0), Some(1), Some(5)],
        "found 0, 1, 5; index 30 lies past the gap"
    );
    assert_eq!(
        f.calls.load(SeqCst),
        26,
        "the scan reads up to 20 past the last found index (5): 0..26"
    );
    assert!(found
        .iter()
        .all(|r| r.seed == seed && r.kind == Some(0x0101)));
    assert_eq!(s.account().accounts(seed.clone()).await.unwrap().len(), 3);
    // again: nothing new (the rows are listed already)
    assert!(s.account().restore(req.clone()).await.unwrap().is_empty());
    // control: a gap of 30 reaches index 30
    let wide = Restore {
        gap: 30,
        ..req.clone()
    };
    let more = s.account().restore(wide).await.unwrap();
    assert_eq!(
        more.iter().map(|r| r.index).collect::<Vec<_>>(),
        vec![Some(30)]
    );
    assert_eq!(
        code(
            s.account()
                .restore(Restore {
                    gap: 0,
                    ..req.clone()
                })
                .await
        ),
        "Argument"
    );
    assert_eq!(
        code(
            s.account()
                .restore(Restore {
                    chain: "nope".into(),
                    ..req
                })
                .await
        ),
        "ChainUnknown"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn restore_reads_spread_over_the_list() {
    let reg = vec![ua_at(0x0101, 0, 0)];
    let fakes: Vec<Arc<Fake>> = (0..3).map(|_| fake(&reg, &[])).collect();
    let mut urls = Vec::new();
    for f in &fakes {
        urls.push(serve(f.clone()).await);
    }
    let (s, _m, seed) = with_seed(&urls).await;
    let req = Restore {
        seed,
        chain: "local-testnet".into(),
        kinds: vec![0x0101],
        account: 0,
        gap: 20,
    };
    s.account().restore(req).await.unwrap();
    let n: Vec<usize> = fakes.iter().map(|f| f.calls.load(SeqCst)).collect();
    assert_eq!(n.iter().sum::<usize>(), 21, "0..21");
    assert!(
        n.iter().all(|c| *c == 7),
        "every endpoint read a third: {n:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn watch_row_signs_nothing() {
    let (s, _m, seed) = with_seed(&[]).await;
    let a = s.account();
    let w = a
        .add_watch(AddWatch {
            seed: seed.clone(),
            watch: ua_at(0x0101, 7, 0),
            name: "watched".into(),
        })
        .await
        .unwrap();
    assert_eq!(w.shape, "watch");
    assert!(
        !a.signs(seed.clone(), w.id.clone()).await.unwrap(),
        "a watch row signs nothing"
    );
    let k = a.add_ua(ua_req(&seed, 0x0101, 0, 0)).await.unwrap();
    assert!(
        a.signs(seed.clone(), k.id).await.unwrap(),
        "control: a UA row signs"
    );
    assert_eq!(code(a.signs(seed.clone(), "nope".into()).await), "Argument");
    let bad = AddWatch {
        seed,
        watch: "0x1234".into(),
        name: "short".into(),
    };
    assert_eq!(
        code(a.add_watch(bad).await),
        "Argument",
        "an id of neither 20 nor 32 bytes"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn delegated_eoa_marked() {
    let w = Wallet::from_mnemonic(REPO, "").unwrap();
    let addr = |i: u32| {
        w.native_key(scaas_ua::wallet::Network::Evm, i, None)
            .unwrap()
            .address()
            .unwrap()
            .to_ascii_lowercase()
    };
    let designator = format!("0xef0100{}", "ab".repeat(20));
    let f = fake(&[], &[(addr(0), designator)]);
    let url = serve(f).await;
    let (s, _m, seed) = with_seed(&[url]).await;
    let a = s.account();
    let d = a
        .add_native(AddNative {
            seed: seed.clone(),
            network: "evm".into(),
            index: 0,
            name: "delegated".into(),
        })
        .await
        .unwrap();
    let p = a
        .add_native(AddNative {
            seed: seed.clone(),
            network: "evm".into(),
            index: 1,
            name: "plain".into(),
        })
        .await
        .unwrap();
    assert_eq!(d.id_text.to_ascii_lowercase(), addr(0));
    let rows = a.marks(seed, "local-testnet".into()).await.unwrap();
    let of = |id: &str| rows.iter().find(|r| r.id == id).unwrap().delegated;
    assert!(
        of(&d.id),
        "an EVM account whose code is 0xef0100… carries the mark"
    );
    assert!(!of(&p.id), "control: an EOA without code");
}

/// P2-3: `marks` reads through the session's pool, pinned to the profile's `chain_uid`: it runs on a `strict_majority` profile
/// (a pool without the pinned uid is refused there).
#[tokio::test(flavor = "multi_thread")]
async fn marks_on_a_strict_majority_profile() {
    let f = fake(&[], &[]);
    let urls = [serve(f.clone()).await, serve(f).await];
    let mut p = profile(&urls);
    p.rpc_policy = scaas_rpc::Policy::StrictMajority;
    let s = Sdk::open(SdkConfig {
        profiles: vec![p],
        store: MemoryStore::new(),
        authenticator: None,
        rp_id: None,
        runtime: RuntimeChoice::Adopt(tokio::runtime::Handle::current()),
        limits: Limits::default(),
        clock: None,
        gas_tables: vec![],
    })
    .await
    .unwrap();
    let req = ImportWords {
        label: "main".into(),
        words: sec(REPO),
        vault_passphrase: sec(PASS),
    };
    let seed = s.vault().import_words(req).await.unwrap().id;
    s.account()
        .add_native(AddNative {
            seed: seed.clone(),
            network: "evm".into(),
            index: 0,
            name: "plain".into(),
        })
        .await
        .unwrap();
    let rows = s
        .account()
        .marks(seed, "local-testnet".into())
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert!(!rows[0].delegated);
}

#[tokio::test(flavor = "multi_thread")]
async fn names_bounded() {
    let (s, _m, seed) = with_seed(&[]).await;
    let mut r = ua_req(&seed, 0x0101, 0, 0);
    r.name = "a\u{202e}b\n".into();
    assert_eq!(
        code(s.account().add_ua(r.clone()).await),
        "Argument",
        "a control character"
    );
    // owner 2026-11-18, Q2: each bidi or format (`Cf`) character alone refuses the name
    for c in [
        '\u{200E}', '\u{200F}', '\u{202A}', '\u{202E}', '\u{2066}', '\u{2069}', '\u{200B}',
        '\u{FEFF}',
    ] {
        r.name = format!("pay{c}ee");
        assert_eq!(
            code(s.account().add_ua(r.clone()).await),
            "Argument",
            "{:#x}",
            u32::from(c)
        );
    }
    r.name = "payée 中".into();
    assert_eq!(
        code(
            s.account()
                .add_watch(AddWatch {
                    seed: seed.clone(),
                    watch: format!("0x{}", "ab".repeat(20)),
                    name: r.name.clone()
                })
                .await
        ),
        "Ok",
        "control: letters with accents and CJK"
    );
    r.name = "x".repeat(65);
    assert_eq!(
        code(s.account().add_ua(r.clone()).await),
        "Argument",
        "above 64 bytes"
    );
    r.name = "x".repeat(64);
    assert_eq!(code(s.account().add_ua(r).await), "Ok", "control: 64 bytes");
}

/// Closing review P3: a registry answer that is not one ABI `bool` word (an endpoint's one byte `0x01`) registers nothing; the
/// word answer of the same endpoint does (the control, `restore_gap_scan`).
#[tokio::test(flavor = "multi_thread")]
async fn restore_reads_a_whole_bool_word() {
    let f = fake(&[ua_at(0x0101, 0, 0)], &[]);
    f.short.store(true, SeqCst);
    let url = serve(f.clone()).await;
    let (s, _m, seed) = with_seed(&[url]).await;
    let req = Restore {
        seed: seed.clone(),
        chain: "local-testnet".into(),
        kinds: vec![0x0101],
        account: 0,
        gap: 3,
    };
    assert!(
        s.account().restore(req.clone()).await.unwrap().is_empty(),
        "a short answer"
    );
    f.short.store(false, SeqCst);
    assert_eq!(
        s.account().restore(req).await.unwrap().len(),
        1,
        "control: the word"
    );
}
