// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! SDK plan T36's read part (decisions CLI-SDK-32 Q-D4: Esplora for balances and history, Bitcoin Core for sends and
//! cross-checks; CLI-SDK-33 (32)): `scaas_rpc::bitcoin`. Fixtures under `tests/fixtures/bitcoin/`:
//! - `esplora_*`: answers recorded on 2026-11-22 from the public Blockstream Esplora of Bitcoin testnet3 (read-only), for two
//!   `ua-rs` addresses of `smartcontracts/vectors/native/native.json`: `bip39_abandon_trezor`'s `m/84'/1'/0'/0/0`
//!   (`tb1qfwxz…agrr`, one UTXO) and `bip39_abandon`'s `m/84'/1'/0'/0/0` (`tb1q6rz2…vkl`, no UTXO, two history pages);
//! - `core_*`: answers recorded the same day from a local regtest `bitcoind` 28.1 (Docker, 1 GB, 1 CPU, stopped and removed
//!   after; controller call CLI-SDK-33 (32)), JSON-RPC 2.0: block 0, the count, the tip's hash, a height above the tip (-8), an
//!   unspent coinbase paying the same `ua-rs` key's script (`0014 4b8c…c96e`) and an output the regtest wallet spent (null).
//!
//! The cross-check tests join the two: a fake Core answering in the recorded shapes with Esplora's testnet3 values (its block 0,
//! its tip hash at the tip height, the UTXO's value), the script unchanged (the same key on both networks). Every refusal
//! beside its control.
#![cfg(feature = "bitcoin")]
mod common;
use common::*;
use scaas_rpc::bitcoin::{cross_check, BitcoinCrossCheck, Core, Esplora, Utxo};
use scaas_rpc::family::{Client, FamilyError};
use scaas_rpc::{EndpointAuth, FailureKind, Secret};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

const TESTNET: &str = "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943";
const REGTEST: &str = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206";
const TIP: u64 = 5372661;
const TIP_HASH: &str = "0000000000b5ad5c47bf92e295bb078868e235b5ab92ff819448b85261abd807";
const FUNDED: &str = "tb1qfwxzlmn42rh6wu6gt4f0yrfpe4gf0jtwgxagrr";
const EMPTY: &str = "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl";
const SCRIPT: &str = "00144b8c2fee7550efa773485d52f20d21cd5097c96e";
const UTXO_TXID: &str = "48cdf56cc1151a98a584f98a7dca36de5f02dd5a6156ebef378a2e0da6269b71";
const UTXO_VALUE: u64 = 60060198;
const COINBASE: &str = "b8c3a10761c7a0eb5a5c3c3955ae48210a473387dbc69b9a25b3f43b21df8679";

fn esplora_fixture(name: &str) -> &'static str {
    match name {
        "genesis" => include_str!("fixtures/bitcoin/esplora_genesis.txt"),
        "tip_height" => include_str!("fixtures/bitcoin/esplora_tip_height.txt"),
        "tip_hash" => include_str!("fixtures/bitcoin/esplora_tip_hash.txt"),
        "utxo" => include_str!("fixtures/bitcoin/esplora_utxo.json"),
        "empty_utxo" => include_str!("fixtures/bitcoin/esplora_empty_utxo.json"),
        "history_p1" => include_str!("fixtures/bitcoin/esplora_history_p1.json"),
        "history_p2" => include_str!("fixtures/bitcoin/esplora_history_p2.json"),
        "fees" => include_str!("fixtures/bitcoin/esplora_fee_estimates.json"),
        "status" => include_str!("fixtures/bitcoin/esplora_tx_status.json"),
        _ => unreachable!(),
    }
}

fn core_fixture(name: &str) -> Value {
    let s = match name {
        "genesis" => include_str!("fixtures/bitcoin/core_genesis.json"),
        "count" => include_str!("fixtures/bitcoin/core_count.json"),
        "tip_hash" => include_str!("fixtures/bitcoin/core_tip_hash.json"),
        "above_tip" => include_str!("fixtures/bitcoin/core_above_tip.json"),
        "unspent" => include_str!("fixtures/bitcoin/core_txout_unspent.json"),
        "spent" => include_str!("fixtures/bitcoin/core_txout_spent.json"),
        _ => unreachable!(),
    };
    serde_json::from_str(s).unwrap()
}

/// The paths an Esplora fake was asked.
type Seen = Arc<Mutex<Vec<String>>>;

/// A replacement answer `(status, body)` for a path, or none.
type Edit = fn(&str) -> Option<(u16, Vec<u8>)>;

/// An Esplora answering from the recorded testnet3 answers; `edit` may replace an answer by path.
async fn esplora(seen: Seen, edit: Edit) -> String {
    serve(axum::Router::new().fallback(move |uri: axum::http::Uri| {
        let seen = seen.clone();
        async move {
            let p = uri.path().to_string();
            seen.lock().unwrap().push(p.clone());
            if let Some((s, b)) = edit(&p) {
                return (axum::http::StatusCode::from_u16(s).unwrap(), b);
            }
            let name = match p.as_str() {
                "/block-height/0" => "genesis",
                "/blocks/tip/height" => "tip_height",
                x if x == format!("/block-height/{TIP}") => "tip_hash",
                x if x == format!("/address/{FUNDED}/utxo") => "utxo",
                x if x == format!("/address/{EMPTY}/utxo") => "empty_utxo",
                x if x == format!("/address/{EMPTY}/txs") => "history_p1",
                x if x.starts_with(&format!("/address/{EMPTY}/txs/chain/")) => "history_p2",
                "/fee-estimates" => "fees",
                x if x == format!("/tx/{UTXO_TXID}/status") => "status",
                _ => return (axum::http::StatusCode::NOT_FOUND, b"not found".to_vec()),
            };
            (
                axum::http::StatusCode::OK,
                esplora_fixture(name).as_bytes().to_vec(),
            )
        }
    }))
    .await
}

fn no_edit(_: &str) -> Option<(u16, Vec<u8>)> {
    None
}

fn esp(urls: &[&str]) -> Esplora {
    let urls: Vec<String> = urls.iter().map(|u| u.to_string()).collect();
    Esplora::new(Client::of_urls(&urls, None).unwrap(), TESTNET)
}

/// Each Core request's authorization header and body.
type Asked = Arc<Mutex<Vec<(Option<String>, Value)>>>;

/// A Core answering `f(request)`'s result or error object, recording each request's authorization header and body.
async fn core_fake(auth: Asked, f: fn(&Value) -> Value) -> String {
    serve(axum::Router::new().fallback(
        move |h: axum::http::HeaderMap, axum::Json(r): axum::Json<Value>| {
            let auth = auth.clone();
            async move {
                auth.lock().unwrap().push((
                    h.get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_string),
                    r.clone(),
                ));
                let mut a = f(&r);
                a["id"] = r["id"].clone();
                axum::Json(a)
            }
        },
    ))
    .await
}

/// The recorded regtest Core.
fn regtest(r: &Value) -> Value {
    let p = &r["params"];
    match r["method"].as_str().unwrap() {
        "getblockhash" if p[0] == 0 => core_fixture("genesis"),
        "getblockhash" if p[0] == 103 => core_fixture("tip_hash"),
        "getblockhash" => core_fixture("above_tip"),
        "getblockcount" => core_fixture("count"),
        "gettxout" if p[0] == COINBASE => core_fixture("unspent"),
        "gettxout" => core_fixture("spent"),
        _ => json!({"jsonrpc": "2.0", "error": {"code": -32601, "message": "Method not found"}}),
    }
}

/// A Core in the recorded shapes with testnet3's values: block 0, the tip hash at [`TIP`], the UTXO unspent with its value.
fn joint(r: &Value) -> Value {
    let p = &r["params"];
    let mut v = match r["method"].as_str().unwrap() {
        "getblockhash" if p[0] == 0 => json!({"jsonrpc": "2.0", "result": TESTNET}),
        "getblockhash" if p[0] == TIP => json!({"jsonrpc": "2.0", "result": TIP_HASH}),
        "gettxout" if p[0] == UTXO_TXID && p[1] == 0 => {
            let mut u = core_fixture("unspent");
            u["result"]["value"] = json!(UTXO_VALUE as f64 / 1e8);
            u
        }
        _ => regtest(r),
    };
    v["jsonrpc"] = json!("2.0");
    v
}

fn core(urls: &[&str], genesis: &str) -> Core {
    let urls: Vec<String> = urls.iter().map(|u| u.to_string()).collect();
    let k = |_| {
        Some(EndpointAuth::Header {
            name: "authorization".into(),
            value: Secret::new("Basic c2NhYXM6cmVndGVzdA=="),
        })
    };
    Core::new(Client::of_urls_each(&urls, k).unwrap(), genesis)
}

fn kind(e: FamilyError) -> FailureKind {
    match e {
        FamilyError::Failure(f) => f.kind,
        e => panic!("{e:?}"),
    }
}

/// The positive control of Esplora's reads: the tip (height and hash), the funded address's UTXO, an address without one,
/// two history pages (the second after the first's last confirmed id), a transaction's height, the fee estimates in msat/vB.
#[tokio::test]
async fn esplora_reads_the_recorded_answers() {
    let seen: Seen = Default::default();
    let e = esp(&[&esplora(seen.clone(), no_edit).await]);
    assert_eq!(e.tip(0).await.unwrap(), (TIP, TIP_HASH.to_string()));
    assert_eq!(
        e.utxos(0, FUNDED).await.unwrap(),
        vec![Utxo {
            txid: UTXO_TXID.into(),
            vout: 0,
            value: UTXO_VALUE,
            height: Some(4968765)
        }]
    );
    assert!(e.utxos(0, EMPTY).await.unwrap().is_empty());
    let p1 = e.history(0, EMPTY, None).await.unwrap();
    assert_eq!(p1.len(), 25);
    assert_eq!(&p1[0].txid[..8], "2e79aa40");
    let last = &p1.iter().rev().find(|t| t.height.is_some()).unwrap().txid;
    let p2 = e.history(0, EMPTY, Some(last)).await.unwrap();
    assert_eq!((p2.len(), &p2[0].txid[..8]), (25, "41e0bf53"));
    assert!(seen
        .lock()
        .unwrap()
        .contains(&format!("/address/{EMPTY}/txs/chain/{last}")));
    assert_eq!(e.tx_height(0, UTXO_TXID).await.unwrap(), Some(4968765));
    let f = e.fee_estimates(0).await.unwrap();
    assert_eq!(f.first(), Some(&(1, 2000)));
    assert!(f.contains(&(7, 263787)));
    assert!(f.windows(2).all(|w| w[0].0 < w[1].0));
    // a rate of three decimals is that many msat/vB, never one more by the float's last bit (2.007 × 1000 = 2007.0000000000002)
    fn three_decimals(p: &str) -> Option<(u16, Vec<u8>)> {
        (p == "/fee-estimates").then(|| (200, br#"{"1":2.007}"#.to_vec()))
    }
    let e = esp(&[&esplora(Default::default(), three_decimals).await]);
    assert_eq!(e.fee_estimates(0).await.unwrap(), vec![(1, 2007)]);
}

/// CLI-RPC-03: an Esplora of another network (its block 0 regtest's) is refused before its reads. Control: testnet3's.
#[tokio::test]
async fn esplora_of_another_network_is_refused() {
    fn regtest_zero(p: &str) -> Option<(u16, Vec<u8>)> {
        (p == "/block-height/0").then(|| (200, REGTEST.as_bytes().to_vec()))
    }
    let other = esplora(Default::default(), regtest_zero).await;
    assert_eq!(
        kind(esp(&[&other]).tip(0).await.unwrap_err()),
        FailureKind::WrongChain
    );
    let good = esplora(Default::default(), no_edit).await;
    assert!(esp(&[&good]).tip(0).await.is_ok(), "control");
}

/// The bounds: a UTXO value above 21 million BTC, a txid of 31 bytes, a confirmed status without a height, a list of 1001
/// UTXOs, a text answer above 80 bytes, an address out of the bech32 form (refused before any request), each beside its control.
#[tokio::test]
async fn esplora_answers_out_of_form_are_refused() {
    fn big_value(p: &str) -> Option<(u16, Vec<u8>)> {
        p.ends_with("/utxo").then(|| {
            (
                200,
                esplora_fixture("utxo")
                    .replace("60060198", "2100000000000001")
                    .into_bytes(),
            )
        })
    }
    fn short_txid(p: &str) -> Option<(u16, Vec<u8>)> {
        p.ends_with("/utxo").then(|| {
            (
                200,
                esplora_fixture("utxo")
                    .replace("48cdf56c", "48cdf5")
                    .into_bytes(),
            )
        })
    }
    fn no_height(p: &str) -> Option<(u16, Vec<u8>)> {
        p.ends_with("/utxo").then(|| {
            (
                200,
                esplora_fixture("utxo")
                    .replace("\"block_height\":4968765,", "")
                    .into_bytes(),
            )
        })
    }
    fn many(p: &str) -> Option<(u16, Vec<u8>)> {
        let one: Value = serde_json::from_str(esplora_fixture("utxo")).unwrap();
        p.ends_with("/utxo").then(|| {
            (
                200,
                serde_json::to_vec(&vec![one[0].clone(); 1001]).unwrap(),
            )
        })
    }
    fn long_text(p: &str) -> Option<(u16, Vec<u8>)> {
        (p == "/blocks/tip/height").then(|| (200, vec![b'1'; 81]))
    }
    for (f, why) in [
        (big_value as Edit, "value"),
        (short_txid, "txid"),
        (no_height, "height"),
        (many, "1001"),
    ] {
        let e = esp(&[&esplora(Default::default(), f).await]);
        assert_eq!(
            kind(e.utxos(0, FUNDED).await.unwrap_err()),
            FailureKind::AnswerMalformed,
            "{why}"
        );
    }
    fn deep(p: &str) -> Option<(u16, Vec<u8>)> {
        p.ends_with("/utxo").then(|| {
            (
                200,
                format!("{}{}", "[".repeat(65), "]".repeat(65)).into_bytes(),
            )
        })
    }
    let e = esp(&[&esplora(Default::default(), deep).await]);
    assert_eq!(
        kind(e.utxos(0, FUNDED).await.unwrap_err()),
        FailureKind::AnswerTooDeep,
        "depth 65"
    );
    let e = esp(&[&esplora(Default::default(), long_text).await]);
    assert_eq!(
        kind(e.tip(0).await.unwrap_err()),
        FailureKind::AnswerTooLarge,
        "text"
    );
    let seen: Seen = Default::default();
    let e = esp(&[&esplora(seen.clone(), no_edit).await]);
    for bad in [
        "tb1q/../../blocks",
        "TB1QFWXZLMN42RH6WU6GT4F0YRFPE4GF0JTWGXAGRR",
        "tb1q",
    ] {
        assert!(e.utxos(0, bad).await.is_err(), "{bad}");
    }
    assert!(
        !seen.lock().unwrap().iter().any(|p| p.contains("/address/")),
        "never asked"
    );
    assert_eq!(e.utxos(0, FUNDED).await.unwrap().len(), 1, "control");
}

/// ARCH-POS-15's failover over Esplora: one down and one of another network are passed over.
#[tokio::test]
async fn esplora_failover_passes_one_down_and_another_network() {
    fn regtest_zero(p: &str) -> Option<(u16, Vec<u8>)> {
        (p == "/block-height/0").then(|| (200, REGTEST.as_bytes().to_vec()))
    }
    let (other, good) = (
        esplora(Default::default(), regtest_zero).await,
        esplora(Default::default(), no_edit).await,
    );
    let e = esp(&[DOWN, &other, &good]);
    let a = e
        .client
        .failover(&e, |i| {
            let e = &e;
            async move {
                e.tip(i).await.map_err(|x| match x {
                    FamilyError::Failure(f) => scaas_rpc::pool::ReadError::Failure(f),
                    x => panic!("{x:?}"),
                })
            }
        })
        .await
        .unwrap();
    assert_eq!((a.endpoint, a.value.0), (2, TIP));
    assert_eq!(e.client.pool().identity_of(1), Some(false));
}

/// Core's reads on the recorded regtest answers: its block hashes (none above the tip, -8), an unspent output's value in
/// satoshis and script, a spent one as none, the mempool's spends counted; its credential sent to it.
#[tokio::test]
async fn core_reads_the_recorded_answers() {
    let auth: Asked = Default::default();
    let c = core(&[&core_fake(auth.clone(), regtest).await], REGTEST);
    assert_eq!(
        c.block_hash(0, 103).await.unwrap().as_deref(),
        Some("1e93f8f3ed6c82d11f192729e24ad1eb9b64387b11e81e4d8aa26d32d369eff7")
    );
    assert_eq!(c.block_hash(0, 113).await.unwrap(), None);
    let o = c.txout(0, COINBASE, 0).await.unwrap().unwrap();
    assert_eq!((o.value, o.script.as_str()), (5_000_000_000, SCRIPT));
    assert_eq!(c.txout(0, &"11".repeat(32), 0).await.unwrap(), None);
    let asked = auth.lock().unwrap();
    assert!(asked
        .iter()
        .all(|(a, _)| a.as_deref() == Some("Basic c2NhYXM6cmVndGVzdA==")));
    // the mempool's spends count: an output spent by a pending transaction is not offered
    assert!(asked
        .iter()
        .filter(|(_, r)| r["method"] == "gettxout")
        .all(|(_, r)| r["params"][2] == true));
}

/// Core of another network is refused before its reads; control: its own genesis.
#[tokio::test]
async fn core_of_another_network_is_refused() {
    let u = core_fake(Default::default(), regtest).await;
    assert_eq!(
        kind(core(&[&u], TESTNET).block_hash(0, 1).await.unwrap_err()),
        FailureKind::WrongChain
    );
    assert!(
        core(&[&u], REGTEST).block_hash(0, 1).await.is_ok(),
        "control"
    );
}

/// `BitcoinCrossCheck`: Esplora's tip and UTXO agree with Core (control); each change alone is refused by name: another tip
/// hash at that height, the output spent in Core, another value, another script.
#[tokio::test]
async fn the_cross_check_refuses_each_disagreement() {
    let e = esp(&[&esplora(Default::default(), no_edit).await]);
    let (tip, utxos) = (e.tip(0).await.unwrap(), e.utxos(0, FUNDED).await.unwrap());
    let ok = core(&[&core_fake(Default::default(), joint).await], TESTNET);
    assert_eq!(
        cross_check(&ok, 0, &tip, &utxos, SCRIPT).await,
        Ok(()),
        "control"
    );
    let forked = (tip.0, "00".repeat(32));
    assert_eq!(
        cross_check(&ok, 0, &forked, &utxos, SCRIPT).await,
        Err(BitcoinCrossCheck::Tip { height: TIP })
    );
    let mut gone = utxos.clone();
    gone[0].vout = 1;
    assert_eq!(
        cross_check(&ok, 0, &tip, &gone, SCRIPT).await,
        Err(BitcoinCrossCheck::Spent {
            txid: UTXO_TXID.into(),
            vout: 1
        })
    );
    let mut more = utxos.clone();
    more[0].value += 1;
    let out = Err(BitcoinCrossCheck::Output {
        txid: UTXO_TXID.into(),
        vout: 0,
    });
    assert_eq!(cross_check(&ok, 0, &tip, &more, SCRIPT).await, out);
    let other = "0014".to_string() + &"00".repeat(20);
    assert_eq!(cross_check(&ok, 0, &tip, &utxos, &other).await, out);
}
