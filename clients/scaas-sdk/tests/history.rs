// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T14: history, watching, events (spec §8.4, §14; R17), against the fake chain of `tests/common/fake_chain.rs` (local
//! only). Every refusal beside its control.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic
)]

#[path = "common/fake_chain.rs"]
mod fake_chain;

use fake_chain::{fake, hash_of, keccak_hex, serve, Fake, CHAIN_ID};
use scaas_sdk::account::AddWatch;
use scaas_sdk::vault::{ImportWords, MemoryStore, SecureStore};
use scaas_sdk::wallet::Cursor;
use scaas_sdk::{
    ChainProfile, EndpointConfig, Event, Family, Finality, Limits, ListedToken, RuntimeChoice, Sdk,
    SdkConfig, SdkError,
};
use scaas_ua::wallet::SecretBytes;
use serde_json::{json, Value};
use std::sync::Arc;
use zeroize::Zeroizing;

const PASS: &str = "river-otter-7 ünï";
const REPO: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";
const ACC: &str = "0x00000000000000000000000000000000000000000000000000000000000acc01";
const OTHER: &str = "0x00000000000000000000000000000000000000000000000000000000000b0b02";

fn token_addr(i: usize) -> String {
    format!("0x5ca00000000000000000000000000000000000{:02x}", 0xa1 + i)
}

fn sec(b: &[u8]) -> Arc<SecretBytes> {
    Arc::new(SecretBytes::from_zeroizing(Zeroizing::new(b.to_vec())).unwrap())
}

fn code<T>(r: Result<T, SdkError>) -> &'static str {
    r.map_or_else(|e| e.code(), |_| "Ok")
}

/// A fake chain with `n` listed tokens (balance 1000 each), head and final block `fin`.
async fn chain(n: usize, fin: u64) -> (Fake, String) {
    let c = fake();
    {
        let mut g = c.lock().unwrap();
        g.head = fin;
        g.finalized = fin;
        for i in 0..n {
            g.tokens.insert(
                token_addr(i),
                (format!("T{i}"), format!("T{i}"), 0, hash_of(0)),
            );
            g.balances.insert(token_addr(i), 1_000);
        }
    }
    let url = serve(c.clone()).await;
    (c, url)
}

async fn open(url: &str, n: usize, store: Arc<dyn SecureStore>, limits: Limits) -> Arc<Sdk> {
    let profile = ChainProfile {
        key: "local".into(),
        family: Family::Evm,
        chain_id: Some(CHAIN_ID),
        chain_uid: hash_of(0),
        rpc: vec![EndpointConfig {
            url: url.into(),
            class: scaas_rpc::Class::Named,
            label: None,
            auth: None,
        }],
        rpc_policy: scaas_rpc::Policy::Failover,
        gateways: vec![],
        registry: None,
        factory: None,
        router: None,
        finality: Finality::Finalized,
        tx_gas_cap: Some(1 << 24),
        gas: Default::default(),
        max_valid_secs: None,
        verifiers: vec![],
        verifier_policy: scaas_rpc::Policy::Failover,
        gas_opt_in: vec![],
        dexes: vec![],
        wrappers: vec![],
        tokens: (0..n)
            .map(|i| ListedToken {
                address: token_addr(i),
                symbol: format!("T{i}"),
                decimals: 0,
            })
            .collect(),
        l1_fee: None,
        pinned_reads: true,
        disabled_kinds: vec![],
        family_params: None,
    };
    Sdk::open(SdkConfig {
        profiles: vec![profile],
        store,
        authenticator: None,
        rp_id: None,
        runtime: RuntimeChoice::Adopt(tokio::runtime::Handle::current()),
        limits,
        clock: None,
        gas_tables: vec![],
    })
    .await
    .unwrap()
}

/// A seed whose watch row names `ACC`.
async fn with_row(sdk: &Arc<Sdk>) {
    let seed = sdk
        .vault()
        .import_words(ImportWords {
            label: "main".into(),
            words: sec(REPO.as_bytes()),
            vault_passphrase: sec(PASS.as_bytes()),
        })
        .await
        .unwrap()
        .id;
    sdk.account()
        .add_watch(AddWatch {
            seed,
            watch: ACC.into(),
            name: "acc".into(),
        })
        .await
        .unwrap();
}

/// A `UATransfer` of `token` from `from` to `to` in block `n` at index `i`.
fn transfer(token: &str, from: &str, to: &str, n: u64, i: u64) -> Value {
    json!({"address": token, "topics": [keccak_hex(b"UATransfer(bytes32,bytes32,uint256)"), from, to],
        "data": format!("0x{:064x}", 5), "blockNumber": format!("{n:#x}"), "blockHash": hash_of(n),
        "transactionHash": format!("0x{:064x}", n * 1000 + i), "transactionIndex": "0x0", "logIndex": format!("{i:#x}"),
        "removed": false})
}

/// The `[from, to]` of every `eth_getLogs` request the fake received.
fn log_ranges(c: &Fake) -> Vec<(u64, u64)> {
    let num =
        |v: &Value| u64::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    let mut out = vec![];
    for body in &c.lock().unwrap().requests {
        let v: Value = serde_json::from_str(body).unwrap();
        let reqs = match v {
            Value::Array(a) => a,
            r => vec![r],
        };
        for r in reqs.iter().filter(|r| r["method"] == "eth_getLogs") {
            let f = &r["params"][0];
            out.push((num(&f["fromBlock"]), num(&f["toBlock"])));
        }
    }
    out
}

async fn events(s: &scaas_sdk::Subscription) -> Vec<Event> {
    let mut out = vec![];
    while let Some(e) = s.next(50).await {
        out.push(e);
    }
    out
}

/// T26 B2-4 (CLI-RPC-07): an endpoint answering logs outside the filter or the range it was asked (another contract, a
/// block above the final one) fails the read, `AnswerMalformed`, never shows them; the control filters and answers.
#[tokio::test(flavor = "multi_thread")]
async fn history_refuses_logs_outside_the_filter() {
    let (c, url) = chain(2, 25_000).await;
    {
        let mut g = c.lock().unwrap();
        g.logs.push(transfer(&token_addr(0), ACC, OTHER, 24_000, 1));
        g.logs
            .push(transfer(&token_addr(0), ACC, OTHER, 1_000_000, 0)); // above the range asked
    }
    let sdk = open(&url, 2, MemoryStore::new(), Limits::default()).await;
    let w = sdk.wallet();
    let p = w
        .history(ACC.into(), "local".into(), None, 10)
        .await
        .unwrap();
    assert_eq!(p.items.len(), 1, "control: the filter answered");
    // the address and topics filtered, the range not: the log above the range alone is the endpoint's failure
    c.lock().unwrap().logs_unranged = true;
    match w.history(ACC.into(), "local".into(), None, 10).await {
        Err(SdkError::Rpc(scaas_rpc::RpcError::EndpointAllFailed { last: Some(l), .. })) => {
            assert_eq!(l.kind, scaas_rpc::FailureKind::AnswerMalformed, "unranged")
        }
        r => panic!("unranged: {:?}", r.map(|p| p.items.len())),
    }
    c.lock().unwrap().logs_unranged = false;
    for other in [false, true] {
        {
            let mut g = c.lock().unwrap();
            g.logs_unfiltered = true;
            if other {
                g.logs.pop();
                // another contract's
                g.logs.push(transfer(
                    "0x00000000000000000000000000000000000000ff",
                    ACC,
                    OTHER,
                    24_100,
                    0,
                ));
            }
        }
        match w.history(ACC.into(), "local".into(), None, 10).await {
            Err(SdkError::Rpc(scaas_rpc::RpcError::EndpointAllFailed {
                last: Some(l), ..
            })) => {
                assert_eq!(l.kind, scaas_rpc::FailureKind::AnswerMalformed, "{other}")
            }
            r => panic!("{other}: {:?}", r.map(|p| p.items.len())),
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn history_pages_with_logs_range() {
    let (c, url) = chain(2, 25_000).await;
    {
        let mut g = c.lock().unwrap();
        let (a, b) = (token_addr(0), token_addr(1));
        g.logs.push(transfer(&a, ACC, OTHER, 24_000, 1));
        g.logs.push(transfer(&b, OTHER, ACC, 24_500, 0));
        g.logs.push(transfer(&a, ACC, OTHER, 24_000, 3));
        g.logs.push(transfer(&a, OTHER, OTHER, 24_100, 0)); // not the account's
        g.logs.push(transfer(&a, ACC, OTHER, 5_000, 0));
    }
    let sdk = open(&url, 2, MemoryStore::new(), Limits::default()).await;
    let w = sdk.wallet();
    assert_eq!(
        code(w.history(ACC.into(), "local".into(), None, 0).await),
        "Argument"
    );
    let p = w
        .history(ACC.into(), "local".into(), None, 2)
        .await
        .unwrap();
    let pos: Vec<(u64, u64)> = p.items.iter().map(|i| (i.block, i.log_index)).collect();
    assert_eq!(pos, vec![(24_500, 0), (24_000, 3)], "newest first, limit");
    assert_eq!(p.items[0].event, "UATransfer");
    assert_eq!(
        p.next,
        Some(Cursor {
            block: 24_000,
            log_index: 3
        })
    );
    let p = w
        .history(ACC.into(), "local".into(), p.next, 10)
        .await
        .unwrap();
    assert_eq!(p.items.len(), 1);
    assert_eq!((p.items[0].block, p.items[0].log_index), (24_000, 1));
    assert!(p.ops.is_empty(), "operations on the first page only");
    // the next window ends at the cursor's block
    assert_eq!(
        p.next,
        Some(Cursor {
            block: 14_000,
            log_index: u64::MAX
        })
    );
    let p = w
        .history(ACC.into(), "local".into(), p.next, 10)
        .await
        .unwrap();
    assert_eq!(
        p.items.iter().map(|i| i.block).collect::<Vec<_>>(),
        vec![5_000]
    );
    assert_eq!(
        p.next,
        Some(Cursor {
            block: 4_000,
            log_index: u64::MAX
        })
    );
    let p = w
        .history(ACC.into(), "local".into(), p.next, 10)
        .await
        .unwrap();
    assert!(p.items.is_empty());
    assert_eq!(p.next, None, "block 0 reached");
    let ranges = log_ranges(&c);
    // three requests (indexed fields 1, 2, 3) per page, each with both bounds and one span window
    assert_eq!(ranges.len(), 12);
    for (lo, hi) in &ranges {
        assert!(
            lo <= hi && hi - lo < scaas_rpc::evm::LOG_RANGE_MAX,
            "{lo}..{hi}"
        );
    }
    assert_eq!(ranges[0], (15_001, 25_000));
    assert_eq!(ranges[3], (14_001, 24_000));
    assert_eq!(ranges[9], (0, 4_000));
}

#[tokio::test(flavor = "multi_thread")]
async fn history_added_and_balance_changed_events() {
    let (c, url) = chain(1, 100).await;
    let sdk = open(&url, 1, MemoryStore::new(), Limits::default()).await;
    with_row(&sdk).await;
    let sub = sdk.subscribe();
    sdk.watch(ACC.into(), vec!["local".into()]).await.unwrap();
    sdk.poll().await.unwrap();
    let ev = events(&sub).await;
    assert!(
        !ev.iter()
            .any(|e| matches!(e, Event::BalanceChanged { .. } | Event::HistoryAdded { .. })),
        "{ev:?}"
    );
    {
        let mut g = c.lock().unwrap();
        g.logs.push(transfer(&token_addr(0), OTHER, ACC, 101, 0));
        g.logs.push(transfer(&token_addr(0), OTHER, ACC, 99, 0)); // before the cursor: never added
        g.head = 110;
        g.finalized = 105;
        g.balances.insert(token_addr(0), 900);
    }
    sdk.poll().await.unwrap();
    let ev = events(&sub).await;
    assert!(ev.contains(&Event::BalanceChanged {
        account: ACC.into(),
        chain: "local".into(),
        token: token_addr(0),
    }));
    let added: Vec<_> = ev
        .iter()
        .filter_map(|e| match e {
            Event::HistoryAdded { items, .. } => Some(items.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(added.len(), 1);
    assert_eq!(
        added[0].iter().map(|i| i.block).collect::<Vec<_>>(),
        vec![101]
    );
    // nothing moved: no event
    sdk.poll().await.unwrap();
    let ev = events(&sub).await;
    assert!(ev.is_empty(), "{ev:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn cursor_resumes_after_restart() {
    let (c, url) = chain(1, 100).await;
    let store = MemoryStore::new();
    let sdk = open(&url, 1, store.clone(), Limits::default()).await;
    with_row(&sdk).await;
    sdk.watch(ACC.into(), vec!["local".into()]).await.unwrap();
    sdk.poll().await.unwrap();
    drop(sdk);
    {
        let mut g = c.lock().unwrap();
        g.logs.push(transfer(&token_addr(0), OTHER, ACC, 103, 0));
        g.head = 200;
        g.finalized = 200;
    }
    let sdk = open(&url, 1, store, Limits::default()).await;
    let sub = sdk.subscribe();
    sdk.watch(ACC.into(), vec!["local".into()]).await.unwrap();
    sdk.poll().await.unwrap();
    let ev = events(&sub).await;
    assert!(
        ev.iter().any(|e| matches!(e, Event::HistoryAdded { items, .. } if items.len() == 1 && items[0].block == 103)),
        "the item between the two runs: {ev:?}"
    );
    assert!(log_ranges(&c).contains(&(101, 200)), "{:?}", log_ranges(&c));
}

#[tokio::test(flavor = "multi_thread")]
async fn lagged_subscriber() {
    let (c, url) = chain(10, 100).await;
    let limits = Limits {
        event_queue: 4,
        ..Limits::default()
    };
    let sdk = open(&url, 10, MemoryStore::new(), limits).await;
    with_row(&sdk).await;
    sdk.watch(ACC.into(), vec!["local".into()]).await.unwrap();
    sdk.poll().await.unwrap();
    let sub = sdk.subscribe();
    {
        let mut g = c.lock().unwrap();
        for i in 0..10 {
            g.balances.insert(token_addr(i), 7);
        }
    }
    // ten events into a queue of four: the poll is not blocked by the subscriber that reads nothing (on a thread of its own,
    // so a producer that blocks fails this test instead of hanging it)
    let (tx, rx) = std::sync::mpsc::channel();
    let (h, s2) = (tokio::runtime::Handle::current(), sdk.clone());
    std::thread::spawn(move || {
        let _ = tx.send(h.block_on(s2.poll()).is_ok());
    });
    let done =
        tokio::task::spawn_blocking(move || rx.recv_timeout(std::time::Duration::from_secs(20)))
            .await
            .unwrap();
    assert_eq!(done, Ok(true), "the SDK blocked on a full queue");
    assert_eq!(sub.next(100).await, Some(Event::Lagged { missed: 6 }));
    let rest = events(&sub).await;
    assert_eq!(rest.len(), 4);
    assert!(rest
        .iter()
        .all(|e| matches!(e, Event::BalanceChanged { .. })));
}

#[tokio::test(flavor = "multi_thread")]
async fn operations_in_history() {
    use scaas_sdk::vault::StorePolicy;
    let (_c, url) = chain(1, 100).await;
    let store = MemoryStore::new();
    let sdk = open(&url, 1, store.clone(), Limits::default()).await;
    let row = |op: &str, from: &str| {
        json!({"op": op, "chain": "local", "entry": "mtxTransfer", "struct": "UATransfer", "kind": "token",
        "contract": token_addr(0), "from": from, "batch": "0", "nonce": "0", "valid_until": 0,
        "digest": format!("0x{}", "00".repeat(32)), "op_json": null, "calldata": "0x", "raw": null, "tx_id": null,
        "tx_nonce": null, "path": "gateway", "payer": null, "from_block": 90, "state": "landed", "detail": "Queued",
        "landed": [95, hash_of(95)], "relayer_bound": false})
    };
    // T26 B2-5: a row holds the account as its 20-byte address or zero-padded to 32 bytes (`op/state.rs`), one account
    let padded = format!("0x{}", &ACC[26..]);
    let st = json!({"rev": 1, "ops": [row("op-mine", &ACC.to_ascii_uppercase().replace("0X", "0x")), row("op-other", OTHER),
        row("op-ids", &padded)]});
    store
        .put_if(
            "sdk.state".into(),
            None,
            serde_json::to_vec(&st).unwrap(),
            StorePolicy::default(),
        )
        .await
        .unwrap();
    let w = sdk.wallet();
    let p = w
        .history(ACC.into(), "local".into(), None, 10)
        .await
        .unwrap();
    assert_eq!(p.ops.len(), 2, "{:?}", p.ops);
    assert_eq!(p.ops[0].op, "op-mine");
    assert_eq!(p.ops[1].op, "op-ids");
    assert_eq!(p.ops[0].state, "landed");
    assert_eq!(p.ops[0].landed_block, Some(95));
    let p = w
        .history(OTHER.into(), "local".into(), None, 10)
        .await
        .unwrap();
    assert_eq!(p.ops[0].op, "op-other");
}

#[tokio::test(flavor = "multi_thread")]
async fn watch_cap() {
    let (c, url) = chain(5, 100).await;
    let limits = Limits {
        max_watch: 2,
        ..Limits::default()
    };
    let store = MemoryStore::new();
    let sdk = open(&url, 5, store.clone(), limits).await;
    with_row(&sdk).await;
    sdk.watch(ACC.into(), vec!["local".into()]).await.unwrap();
    let calls = |c: &Fake| {
        c.lock()
            .unwrap()
            .requests
            .iter()
            .filter(|b| {
                b.contains("balanceOfUA") || b.contains(&keccak_hex(b"balanceOfUA(bytes32)")[2..10])
            })
            .count()
    };
    let cursors = || async {
        let st: Value = serde_json::from_slice(
            &store
                .get("sdk.state".into(), String::new())
                .await
                .unwrap()
                .unwrap()
                .bytes,
        )
        .unwrap();
        let mut k: Vec<String> = st["cursors"].as_object().unwrap().keys().cloned().collect();
        k.sort();
        k
    };
    let key = |i: usize| format!("local|{ACC}|{}", token_addr(i));
    // two triples per poll, the rest next poll, round robin
    let mut seen = vec![];
    let mut keys = vec![];
    for _ in 0..3 {
        let before = calls(&c);
        sdk.poll().await.unwrap();
        seen.push(calls(&c) - before);
        keys.push(cursors().await);
    }
    assert_eq!(seen, vec![2, 2, 2]);
    assert_eq!(keys[0], vec![key(0), key(1)]);
    assert_eq!(keys[1], vec![key(0), key(1), key(2), key(3)]);
    assert_eq!(keys[2].len(), 5);
}

#[tokio::test(flavor = "multi_thread")]
async fn no_hidden_set_cursor() {
    let (_c, url) = chain(1, 100).await;
    let store = MemoryStore::new();
    let sdk = open(&url, 1, store.clone(), Limits::default()).await;
    with_row(&sdk).await;
    let state = || async {
        store
            .get("sdk.state".into(), String::new())
            .await
            .unwrap()
            .map(|i| String::from_utf8(i.bytes).unwrap())
    };
    // an id no keystore row names (a hidden set's account is never written): not watched, no cursor
    assert_eq!(
        code(sdk.watch(OTHER.into(), vec!["local".into()]).await),
        "Argument"
    );
    sdk.poll().await.unwrap();
    assert_eq!(state().await, None);
    // its history is read and writes nothing
    sdk.wallet()
        .history(OTHER.into(), "local".into(), None, 5)
        .await
        .unwrap();
    assert_eq!(state().await, None);
    // control: the row's account gets its cursor
    sdk.watch(ACC.into(), vec!["local".into()]).await.unwrap();
    sdk.poll().await.unwrap();
    let s = state().await.unwrap();
    assert!(s.contains(&format!("local|{ACC}|{}", token_addr(0))), "{s}");
    assert!(!s.contains(&OTHER[2..]), "{s}");
}

#[tokio::test(flavor = "multi_thread")]
async fn state_changed_from_another_process() {
    let (_c, url) = chain(1, 100).await;
    let d = std::env::temp_dir().join(format!("scaas-sdk-state-two-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    let a = open(
        &url,
        1,
        scaas_sdk::vault::FileStore::new(&d).unwrap(),
        Limits::default(),
    )
    .await;
    with_row(&a).await;
    let sub = a.subscribe();
    a.watch(ACC.into(), vec!["local".into()]).await.unwrap();
    let c = _c;
    a.poll().await.unwrap();
    // its own cursor write is no `StateChanged`
    a.poll().await.unwrap();
    let ev = events(&sub).await;
    assert!(
        !ev.iter().any(|e| matches!(e, Event::StateChanged { .. })),
        "{ev:?}"
    );
    // a second SDK over the same directory writes `sdk.state`
    let b = open(
        &url,
        1,
        scaas_sdk::vault::FileStore::new(&d).unwrap(),
        Limits::default(),
    )
    .await;
    b.watch(ACC.into(), vec!["local".into()]).await.unwrap();
    c.lock().unwrap().finalized = 101;
    c.lock().unwrap().head = 101;
    b.poll().await.unwrap();
    let rev = b.state_rev().await.unwrap();
    a.poll().await.unwrap();
    let ev = events(&sub).await;
    assert!(ev.contains(&Event::StateChanged { rev }), "{ev:?}");
    assert_eq!(a.state_rev().await.unwrap(), rev);
    let _ = std::fs::remove_dir_all(&d);
}
