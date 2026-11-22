// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan 2026-11-17-scaas-sdk T30.soroban and T41.soroban (spec §27.3 (c), §27.5 (d)): the bounded `SorobanTransactionData` and
//! auth entry readers against clientkeys' rows (smartcontracts/vectors/native/soroban-tx.json), an oversized and a too-deep
//! input refused beside their controls; `simulateTransaction`, `getLedgerEntries`, `getFeeStats` and `getTransaction` read
//! within their forms; `sendTransaction` per CLI-RPC-08: the id local before any request, the same bytes to every endpoint, an
//! endpoint answering another id not accepting, `DUPLICATE` accepted, a refusal kept with its reason, `Sent` with one accepted,
//! else `Rejected`.
#![cfg(feature = "soroban")]
mod common;
use common::*;
use scaas_rpc::endpoint::Fanout;
use scaas_rpc::family::{Client, SendOutcome};
use scaas_rpc::soroban::{auth_signer, tx_data, tx_id, Broadcast, Simulation, Soroban, TxStatus, XDR_DEPTH, XDR_MAX};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

const PASS: &str = "Standalone Network ; February 2017";

fn rows() -> Value {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../smartcontracts/vectors/native/soroban-tx.json");
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}
fn hexb(v: &Value) -> Vec<u8> {
    hex(v.as_str().unwrap())
}
fn hex(s: &str) -> Vec<u8> {
    let s = s.trim_start_matches("0x");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
fn b64(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(b)
}
fn unb64(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}

#[test]
fn transaction_data_rows_read_to_their_named_fields() {
    let v = rows();
    let invokes: Vec<&Value> = v["rows"].as_array().unwrap().iter().filter(|r| r.get("dataXdr").is_some()).collect();
    assert_eq!(invokes.len(), 2);
    for r in invokes {
        let d = tx_data(&hexb(&r["dataXdr"])).unwrap();
        let n = &r["op"]["invoke"]["data"];
        let keys = |k: &str| n[k].as_array().unwrap().iter().map(|x| unb64(x.as_str().unwrap())).collect::<Vec<_>>();
        assert_eq!(d.read_only, keys("readOnly"));
        assert_eq!(d.read_write, keys("readWrite"));
        assert_eq!(u64::from(d.instructions), n["instructions"].as_u64().unwrap());
        assert_eq!(d.resource_fee.to_string(), n["resourceFee"].as_str().unwrap());
        let archived: Vec<u32> = n["archived"].as_array().unwrap().iter().map(|x| x.as_u64().unwrap() as u32).collect();
        assert_eq!(d.archived, archived);
        // one byte more, or one less, is no transaction data
        let mut b = hexb(&r["dataXdr"]);
        b.push(0);
        assert!(tx_data(&b).is_none());
        assert!(tx_data(&b[..b.len() - 2]).is_none());
    }
}

/// A `ContractData` footprint key whose `ScVal` key is `depth` nested `Vec`s around a `Void`.
fn deep_data(depth: usize) -> Vec<u8> {
    let mut k = vec![0, 0, 0, 6, 0, 0, 0, 1];
    k.extend_from_slice(&[7; 32]);
    for _ in 0..depth {
        k.extend_from_slice(&[0, 0, 0, 16, 0, 0, 0, 1, 0, 0, 0, 1]);
    }
    k.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 1]);
    let mut d = vec![0, 0, 0, 0, 0, 0, 0, 1];
    d.extend_from_slice(&k);
    d.extend_from_slice(&[0; 4 + 12 + 8]);
    d
}

#[test]
fn a_too_deep_or_oversized_transaction_data_is_refused_beside_its_control() {
    // the key's ScVal at the depth bound reads; one level more does not
    assert!(tx_data(&deep_data(XDR_DEPTH as usize - 1)).is_some(), "control");
    assert!(tx_data(&deep_data(XDR_DEPTH as usize)).is_none(), "too deep");
    // a Bytes key of XDR_MAX bytes makes the whole above the bound
    let mut k = vec![0, 0, 0, 6, 0, 0, 0, 1];
    k.extend_from_slice(&[7; 32]);
    let big = |n: usize| {
        let mut k = k.clone();
        k.extend_from_slice(&[0, 0, 0, 13]);
        k.extend_from_slice(&(n as u32).to_be_bytes());
        k.extend(std::iter::repeat_n(0u8, n.div_ceil(4) * 4));
        k.extend_from_slice(&[0, 0, 0, 1]);
        let mut d = vec![0, 0, 0, 0, 0, 0, 0, 1];
        d.extend_from_slice(&k);
        d.extend_from_slice(&[0; 4 + 12 + 8]);
        d
    };
    assert!(tx_data(&big(1024)).is_some(), "control");
    assert!(big(XDR_MAX).len() > XDR_MAX);
    assert!(tx_data(&big(XDR_MAX)).is_none(), "oversized");
    // a list above its count
    let mut many = vec![0, 0, 0, 0, 0, 0, 1, 1];
    many.extend_from_slice(&[0; 4 + 12 + 8]);
    assert!(tx_data(&many).is_none(), "257 keys");
}

/// The auth entry inside the first row's transaction: its signer is T27's subject.
#[test]
fn an_auth_entry_reads_to_its_signer() {
    let v = rows();
    let r = &v["rows"][0];
    let tx = hexb(&r["tx"]);
    let data = hexb(&r["dataXdr"]);
    // the entry sits between the call and the transaction data: find it by its signer's prefix
    let from = r["op"]["invoke"]["auth"][0]["from"].as_str().unwrap();
    let pk = strkey_key(from);
    let mut prefix = vec![0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
    prefix.extend_from_slice(&pk);
    let at = tx.windows(prefix.len()).position(|w| w == prefix.as_slice()).unwrap();
    let end = tx.len() - data.len() - 4;
    let entry = &tx[at..end];
    assert_eq!(auth_signer(entry).unwrap(), &prefix[..]);
    assert!(auth_signer(&entry[..entry.len() - 4]).is_none(), "a cut entry");
    let mut source = entry.to_vec();
    source[3] = 0;
    assert!(auth_signer(&source).is_none(), "source-account credentials");
}

fn strkey_key(s: &str) -> [u8; 32] {
    let mut out = vec![];
    let (mut acc, mut bits) = (0u32, 0);
    for c in s.bytes() {
        let v = if c.is_ascii_uppercase() { c - b'A' } else { c - b'2' + 26 };
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

#[test]
fn the_local_id_is_the_rows_hash() {
    let v = rows();
    let nid: [u8; 32] = hexb(&v["networkId"]).try_into().unwrap();
    for r in v["rows"].as_array().unwrap() {
        assert_eq!(tx_id(&nid, &hexb(&r["tx"])).to_vec(), hexb(&r["hash"]));
    }
}

type Seen = Arc<Mutex<Vec<String>>>;
/// A Soroban RPC answering `getNetwork` with PASS and `method` with `answer` (the transaction text it was sent recorded).
async fn rpc(answer: Value, seen: Seen) -> String {
    serve(axum::Router::new().route(
        "/",
        axum::routing::post(move |axum::Json(r): axum::Json<Value>| {
            let (answer, seen) = (answer.clone(), seen.clone());
            async move {
                let result = match r["method"].as_str() {
                    Some("getNetwork") => json!({"passphrase": PASS, "protocolVersion": 30}),
                    Some("getLatestLedger") => json!({"id": "ab", "sequence": 100}),
                    Some(_) => {
                        if let Some(t) = r["params"]["transaction"].as_str() {
                            seen.lock().unwrap().push(t.to_string());
                        }
                        answer
                    }
                    None => Value::Null,
                };
                axum::Json(json!({"jsonrpc": "2.0", "id": r["id"], "result": result}))
            }
        }),
    ))
    .await
}

fn soroban(urls: &[&str]) -> Soroban {
    let urls: Vec<String> = urls.iter().map(|u| u.to_string()).collect();
    Soroban::new(Client::of_urls(&urls, None).unwrap(), PASS)
}

#[tokio::test]
async fn send_merges_per_cli_rpc_08() {
    let v = rows();
    let r = &v["rows"][2];
    let nid: [u8; 32] = hexb(&v["networkId"]).try_into().unwrap();
    let tx = hexb(&r["tx"]);
    let sig: [u8; 64] = hexb(&r["signature"]).try_into().unwrap();
    let env = hexb(&r["envelope"]);
    let hint: [u8; 4] = env[env.len() - 72..env.len() - 68].try_into().unwrap();
    let id = r["hash"].as_str().unwrap().trim_start_matches("0x").to_string();
    let seen: Seen = Arc::default();
    let pending = rpc(json!({"status": "PENDING", "hash": id, "latestLedger": 100}), seen.clone()).await;
    let dup = rpc(json!({"status": "DUPLICATE", "hash": id.to_uppercase(), "latestLedger": 100}), seen.clone()).await;
    let other = rpc(json!({"status": "PENDING", "hash": "00".repeat(32), "latestLedger": 100}), seen.clone()).await;
    let error = rpc(json!({"status": "ERROR", "hash": id, "errorResultXdr": "AAAAAAAAAGT////7AAAAAA==", "latestLedger": 100}), seen.clone()).await;
    let s = soroban(&[&pending, &dup, &other, &error, DOWN]);
    let b = s.send(&nid, &tx, &[(hint, sig)], Fanout::All).await.unwrap();
    assert_eq!(b.id().to_vec(), hexb(&r["hash"]), "the id is local");
    let Broadcast::Sent { accepted, others, .. } = &b else { panic!("{b:?}") };
    assert_eq!(accepted, &vec![0, 1], "PENDING and DUPLICATE with the id");
    assert_eq!(others.len(), 3);
    assert!(matches!(&others[0], (2, SendOutcome::Refused { reason }) if reason == "another transaction id"));
    assert!(matches!(&others[1], (3, SendOutcome::Refused { reason }) if reason.starts_with("ERROR")));
    assert!(matches!(&others[2], (4, SendOutcome::Unreachable { .. })));
    // the same bytes, the row's envelope, to each endpoint that answered
    let sent = seen.lock().unwrap().clone();
    assert_eq!(sent.len(), 4);
    assert!(sent.iter().all(|t| unb64(t) == env));
    // none accepting: Rejected, with the same id
    let s = soroban(&[&other, &error]);
    let b = s.send(&nid, &tx, &[(hint, sig)], Fanout::All).await.unwrap();
    assert!(matches!(b, Broadcast::Rejected { ref outcomes, .. } if outcomes.len() == 2));
    // the first endpoint only
    let s = soroban(&[&pending, &dup]);
    let b = s.send(&nid, &tx, &[(hint, sig)], Fanout::First).await.unwrap();
    assert!(matches!(b, Broadcast::Sent { ref accepted, ref others, .. } if accepted == &vec![0] && others.is_empty()));
    assert!(s.send(&nid, &tx, &[], Fanout::First).await.is_err(), "no signature");
}

#[tokio::test]
async fn a_simulation_reads_within_its_form() {
    let v = rows();
    let data = b64(&hexb(&v["rows"][0]["dataXdr"]));
    let seen: Seen = Arc::default();
    let ok = rpc(
        json!({"latestLedger": 100, "minResourceFee": "1234567", "transactionData": data, "results": [{"auth": [], "xdr": "AAAAAQ=="}]}),
        seen.clone(),
    )
    .await;
    let s = soroban(&[&ok]);
    let (l, sim) = s.simulate_at(0, b"env").await.unwrap();
    assert_eq!(l, 100);
    let Simulation::Ok { data: d, min_resource_fee, auth } = sim else { panic!() };
    assert_eq!((min_resource_fee, auth.len(), d.read_write.len()), (1_234_567, 0, 4));
    assert_eq!(unb64(&seen.lock().unwrap()[0]), b"env".to_vec(), "the envelope as given");
    let refused = rpc(json!({"latestLedger": 100, "error": "HostError: Error(Auth, InvalidAction)"}), seen.clone()).await;
    let (_, sim) = soroban(&[&refused]).simulate_at(0, b"env").await.unwrap();
    assert!(matches!(sim, Simulation::Refused { ref reason } if reason.contains("Auth")));
    let restore = rpc(json!({"latestLedger": 100, "restorePreamble": {"minResourceFee": "1"}, "transactionData": data, "minResourceFee": "1", "results": [{}]}), seen.clone()).await;
    assert_eq!(soroban(&[&restore]).simulate_at(0, b"env").await.unwrap().1, Simulation::Restore);
    for bad in [
        json!({"latestLedger": 100, "minResourceFee": "1234567", "transactionData": "AAAA", "results": [{}]}),
        json!({"latestLedger": 100, "minResourceFee": "-1", "transactionData": data, "results": [{}]}),
        json!({"latestLedger": 100, "minResourceFee": "1", "transactionData": data, "results": []}),
        json!({"latestLedger": 100, "minResourceFee": "1", "transactionData": data, "results": [{"auth": ["AAAAAA=="]}]}),
        json!({"minResourceFee": "1", "transactionData": data, "results": [{}]}),
    ] {
        let u = rpc(bad.clone(), seen.clone()).await;
        assert!(soroban(&[&u]).simulate_at(0, b"env").await.is_err(), "{bad}");
    }
}

#[tokio::test]
async fn entries_fee_stats_and_status_read_within_their_forms() {
    let seen: Seen = Arc::default();
    let k = vec![vec![0u8, 0, 0, 0], vec![1u8, 1, 1, 1]];
    let e = rpc(json!({"latestLedger": 9, "entries": [{"key": b64(&k[1]), "xdr": "AAAAAQ==", "liveUntilLedgerSeq": 20}]}), seen.clone()).await;
    let (l, got) = soroban(&[&e]).entries_at(0, &k).await.unwrap();
    assert_eq!(l, 9);
    assert_eq!(got[0], None);
    assert_eq!(got[1].as_ref().unwrap().live_until, Some(20));
    let twice = rpc(json!({"latestLedger": 9, "entries": [{"key": b64(&k[1]), "xdr": "AAAAAQ=="}, {"key": b64(&k[1]), "xdr": "AAAAAQ=="}]}), seen.clone()).await;
    assert!(soroban(&[&twice]).entries_at(0, &k).await.is_err());
    let f = rpc(json!({"sorobanInclusionFee": {"p90": "150"}, "inclusionFee": {"p90": "100"}}), seen.clone()).await;
    assert_eq!(soroban(&[&f]).fee_stats_at(0).await.unwrap(), (150, 100));
    let f = rpc(json!({"sorobanInclusionFee": {"p90": 150}, "inclusionFee": {"p90": "100"}}), seen.clone()).await;
    assert!(soroban(&[&f]).fee_stats_at(0).await.is_err(), "a number where the RPC writes text");
    for (a, want) in [
        (json!({"status": "SUCCESS", "ledger": 7, "latestLedger": 9}), Some(TxStatus::Success { ledger: 7 })),
        (json!({"status": "FAILED", "ledger": 8, "latestLedger": 9}), Some(TxStatus::Failed { ledger: 8 })),
        (json!({"status": "NOT_FOUND", "latestLedger": 9}), Some(TxStatus::NotFound { latest: 9 })),
        (json!({"status": "SUCCESS", "latestLedger": 9}), None),
        (json!({"status": "PENDING", "latestLedger": 9}), None),
    ] {
        let u = rpc(a, seen.clone()).await;
        assert_eq!(soroban(&[&u]).transaction_at(0, &[1; 32]).await.ok(), want);
    }
}
