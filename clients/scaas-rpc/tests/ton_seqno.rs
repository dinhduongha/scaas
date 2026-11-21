// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! rpc T24.ton-seqno (plan T24, spec §8.7 TON row): TON getters and the account read pinned to one masterchain seqno, through
//! TON Center's `/api/v2/` paths on the same endpoints (v3's `runGetMethod` and `walletInformation` take no seqno), each answer
//! required to name that masterchain block; the stack's numbers and cells; the bounded BoC reader (`scaas_rpc::boc`). The
//! fixtures under `tests/fixtures/ton-v2/` are answers recorded from the public TON testnet TON Center on 2026-11-21, at
//! masterchain seqno 99410094: a testnet jetton master's `get_wallet_address(owner)`, that wallet's `get_wallet_data`, an
//! uninitialized account's getter (exit code -13) and `getAddressInformation` of both accounts.
#![cfg(feature = "ton")]
mod common;
use common::*;
use scaas_rpc::boc;
use scaas_rpc::family::{Client, FamilyError};
use scaas_rpc::ton::{StackArg, StackEntry, Ton};
use scaas_rpc::FailureKind;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

const SEQNO: u64 = 99410094;
const MASTER: &str = "0:4408958692A3C22D3BA0A881503CAFECE8D53E9DFCE42C6D26C5D8AEDA1742C7";
const OWNER: &str = "0:07CB92CC48939C2B257052341FDA2574085F952DAE424BC8C9E1BACFEC182B3B";
const WALLET: &str = "0:0000018DF410923C4A46BB31F7D66F99C099B806D44943F57C57BBE3E83600CF";

fn fixture(name: &str) -> Value {
    let s = match name {
        "address" => include_str!("fixtures/ton-v2/run_get_wallet_address.json"),
        "data" => include_str!("fixtures/ton-v2/run_get_wallet_data.json"),
        "uninit" => include_str!("fixtures/ton-v2/run_get_uninit.json"),
        "active" => include_str!("fixtures/ton-v2/address_information_active.json"),
        "uninit-account" => include_str!("fixtures/ton-v2/address_information_uninit.json"),
        _ => unreachable!(),
    };
    serde_json::from_str(s).unwrap()
}

/// Each `/api/v2/` request's path with its query, and its body.
type Seen = Arc<Mutex<Vec<(String, Value)>>>;

/// A TON Center answering every `/api/v2/` request with `answer`; its head is [`SEQNO`], its masterchain block `n` has root
/// hash `{fork}{n}`.
async fn center(answer: Value, fork: &'static str, seen: Seen) -> String {
    serve(axum::Router::new().fallback(
        move |uri: axum::http::Uri, body: axum::body::Bytes| {
            let (seen, answer) = (seen.clone(), answer.clone());
            async move {
                let p = uri.path_and_query().map(|p| p.to_string()).unwrap_or_default();
                let ok = |v: Value| (axum::http::StatusCode::OK, serde_json::to_vec(&v).unwrap());
                if p.starts_with("/api/v2/") {
                    seen.lock().unwrap().push((p, serde_json::from_slice(&body).unwrap_or(Value::Null)));
                    ok(answer)
                } else if p.starts_with("/api/v3/masterchainInfo") {
                    ok(json!({"last": {"seqno": SEQNO, "root_hash": "rh"}}))
                } else if p.starts_with("/api/v3/blocks") {
                    let n = p.split("seqno=").nth(1).unwrap_or_default().to_string();
                    ok(json!({"blocks": [{"root_hash": format!("{fork}{n}")}]}))
                } else {
                    (axum::http::StatusCode::NOT_FOUND, b"not found".to_vec())
                }
            }
        },
    ))
    .await
}

fn ton(urls: &[&str]) -> Ton {
    let urls: Vec<String> = urls.iter().map(|u| u.to_string()).collect();
    Ton::new(Client::of_urls_each(&urls, |_| None).unwrap())
}

fn malformed(e: FamilyError) -> bool {
    matches!(e, FamilyError::Failure(f) if f.kind == FailureKind::AnswerMalformed)
}

/// `f` applied to the recorded answer `name`.
fn edited(name: &str, f: impl FnOnce(&mut Value)) -> Value {
    let mut v = fixture(name);
    f(&mut v);
    v
}

fn raw(s: &str) -> (i8, [u8; 32]) {
    scaas_rpc::ton::raw_address(s).unwrap()
}

/// The master's `get_wallet_address(owner)` at the seqno: the request is v2's `runGetMethod` with the seqno and the owner as a
/// slice BoC, the answer's cell the wallet's address.
#[tokio::test]
async fn a_getter_is_asked_at_the_seqno_and_its_cell_read() {
    let seen: Seen = Default::default();
    let n = ton(&[&center(fixture("address"), "b", seen.clone()).await]);
    let (wc, h) = raw(OWNER);
    let g = n
        .run_get_at(0, MASTER, "get_wallet_address", &[StackArg::Slice(boc::address_slice(wc, &h))], SEQNO)
        .await
        .unwrap();
    assert_eq!(g.exit_code, 0);
    let StackEntry::Cell(b) = &g.stack[0] else { panic!("{:?}", g.stack) };
    assert_eq!(boc::std_address(&boc::parse(b).unwrap()), Some(raw(WALLET)));
    let s = seen.lock().unwrap();
    assert_eq!(s[0].0, "/api/v2/runGetMethod");
    assert_eq!(s[0].1["seqno"], SEQNO);
    assert_eq!(s[0].1["method"], "get_wallet_address");
    assert_eq!(s[0].1["address"], MASTER);
    // the slice the endpoint ran on is the owner's address (the recorded run answered this request)
    let arg = &s[0].1["stack"][0];
    assert_eq!(arg[0], "tvm.Slice");
    use base64::Engine as _;
    let sent = base64::engine::general_purpose::STANDARD.decode(arg[1].as_str().unwrap()).unwrap();
    assert_eq!(boc::std_address(&boc::parse(&sent).unwrap()), Some(raw(OWNER)));
}

/// The wallet's `get_wallet_data`: a number and three cells (the owner, the master, the code with its references).
#[tokio::test]
async fn a_stack_of_numbers_and_cells_is_read() {
    let n = ton(&[&center(fixture("data"), "b", Default::default()).await]);
    let g = n.run_get_at(0, WALLET, "get_wallet_data", &[], SEQNO).await.unwrap();
    assert_eq!(g.stack.len(), 4);
    assert_eq!(g.stack[0].as_u128(), Some(101));
    let cell = |k: usize| match &g.stack[k] {
        StackEntry::Cell(b) => boc::parse(b).unwrap(),
        e => panic!("{e:?}"),
    };
    assert_eq!(boc::std_address(&cell(1)), Some(raw(OWNER)));
    assert_eq!(boc::std_address(&cell(2)), Some(raw(MASTER)));
    assert!(!cell(3).refs.is_empty(), "the code cell and its references");
    assert_eq!(boc::std_address(&cell(3)), None, "a code cell is no address");
}

/// An uninitialized account's getter: its exit code as the endpoint gave it, for the caller to read.
#[tokio::test]
async fn a_getters_exit_code_is_the_callers() {
    let n = ton(&[&center(fixture("uninit"), "b", Default::default()).await]);
    let g = n.run_get_at(0, OWNER, "get_wallet_data", &[], SEQNO).await.unwrap();
    assert_eq!(g.exit_code, -13);
}

/// An answer naming another masterchain seqno, a block of another workchain, or `ok` not true: that endpoint's malformed
/// answer. Control: the recorded answer is read.
#[tokio::test]
async fn a_getter_answer_of_another_block_is_malformed() {
    let run = |v: Value| async move {
        let n = ton(&[&center(v, "b", Default::default()).await]);
        n.run_get_at(0, WALLET, "get_wallet_data", &[], SEQNO).await
    };
    run(fixture("data")).await.unwrap();
    for (why, v) in [
        ("another seqno", edited("data", |v| v["result"]["block_id"]["seqno"] = json!(SEQNO + 1))),
        ("another workchain", edited("data", |v| v["result"]["block_id"]["workchain"] = json!(0))),
        ("no block", edited("data", |v| v["result"].as_object_mut().unwrap().remove("block_id").map(|_| ()).unwrap())),
        ("ok false", edited("data", |v| v["ok"] = json!(false))),
        ("an exit code not a number", edited("data", |v| v["result"]["exit_code"] = json!("0"))),
    ] {
        assert!(malformed(run(v).await.unwrap_err()), "{why}");
    }
}

/// The stack's entries: a number is `0x` hex of at most 257 bits (a sign kept), a cell's `bytes` base64; anything else is
/// malformed. Control: `0x` + 65 hex digits and `-0x1` are read (as no u128).
#[tokio::test]
async fn a_stack_entry_out_of_form_is_malformed() {
    let run = |e: Value| async move {
        let v = edited("data", |v| v["result"]["stack"] = json!([e]));
        let n = ton(&[&center(v, "b", Default::default()).await]);
        n.run_get_at(0, WALLET, "get_wallet_data", &[], SEQNO).await
    };
    let long = format!("0x1{}", "0".repeat(64));
    assert_eq!(run(json!(["num", long])).await.unwrap().stack[0].as_u128(), None);
    assert_eq!(run(json!(["num", "-0x1"])).await.unwrap().stack[0].as_u128(), None);
    assert_eq!(run(json!(["num", "0xffffffffffffffffffffffffffffffff"])).await.unwrap().stack[0].as_u128(), Some(u128::MAX));
    for (why, e) in [
        ("66 hex digits", json!(["num", format!("0x1{}", "0".repeat(65))])),
        ("decimal", json!(["num", "101"])),
        ("not hex", json!(["num", "0xg"])),
        ("a number as JSON", json!(["num", 101])),
        ("a cell not base64", json!(["cell", {"bytes": "!!"}])),
        ("a tuple", json!(["tuple", {"elements": []}])),
    ] {
        assert!(malformed(run(e).await.unwrap_err()), "{why}");
    }
}

/// The account at the seqno: v2's `getAddressInformation` with the seqno; its balance (nanoton, decimal) and state.
#[tokio::test]
async fn the_account_is_read_at_the_seqno() {
    let seen: Seen = Default::default();
    let n = ton(&[&center(fixture("active"), "b", seen.clone()).await]);
    let a = n.account_at(0, WALLET, SEQNO).await.unwrap();
    assert_eq!((a.balance.as_str(), a.state.as_str()), ("10000000", "active"));
    let p = seen.lock().unwrap()[0].0.clone();
    assert_eq!(p, format!("/api/v2/getAddressInformation?address={}&seqno={SEQNO}", WALLET.replace(':', "%3A")));
    let n = ton(&[&center(fixture("uninit-account"), "b", Default::default()).await]);
    let a = n.account_at(0, OWNER, SEQNO).await.unwrap();
    assert_eq!((a.balance.as_str(), a.state.as_str()), ("0", "uninitialized"));
}

/// An account answer of another seqno, a balance not a decimal string of at most 78 digits: malformed. Control above.
#[tokio::test]
async fn an_account_answer_out_of_form_is_malformed() {
    for (why, v) in [
        ("another seqno", edited("active", |v| v["result"]["block_id"]["seqno"] = json!(SEQNO - 1))),
        ("ok false", edited("active", |v| v["ok"] = json!(false))),
        ("a balance as a number", edited("active", |v| v["result"]["balance"] = json!(10000000))),
        ("a balance not decimal", edited("active", |v| v["result"]["balance"] = json!("1e7"))),
        ("79 digits", edited("active", |v| v["result"]["balance"] = json!("1".repeat(79)))),
        ("no state", edited("active", |v| v["result"]["state"] = json!(null))),
    ] {
        let n = ton(&[&center(v, "b", Default::default()).await]);
        assert!(malformed(n.account_at(0, WALLET, SEQNO).await.unwrap_err()), "{why}");
    }
}

/// The pinned reads under the failover: endpoint 0 down, a later endpoint of another network (T24.6's root hash) dropped,
/// the next one of this network answers, its stack read.
#[tokio::test]
async fn a_pinned_read_fails_over_past_another_network() {
    let (other, good) = (
        center(fixture("data"), "x", Default::default()).await,
        center(fixture("data"), "b", Default::default()).await,
    );
    let n = ton(&[DOWN, &other, &good]);
    n.saw(7, "b7");
    let a = n
        .client
        .failover(&n, |i| {
            let n = &n;
            async move {
                n.run_get_at(i, WALLET, "get_wallet_data", &[], SEQNO)
                    .await
                    .map_err(|e| match e {
                        FamilyError::Failure(f) => scaas_rpc::pool::ReadError::Failure(f),
                        e => panic!("{e:?}"),
                    })
            }
        })
        .await
        .unwrap();
    assert_eq!((a.endpoint, a.value.stack[0].as_u128()), (2, Some(101)));
    assert_eq!(n.client.pool().identity_of(1), Some(false), "another root hash: dropped");
}

/// `wc:hex` addresses: workchain 0 or -1 and 64 hex digits, any case; anything else none.
#[test]
fn raw_addresses() {
    assert_eq!(raw(WALLET).0, 0);
    assert_eq!(scaas_rpc::ton::raw_address(&MASTER.to_lowercase()), Some(raw(MASTER)));
    assert_eq!(raw(&format!("-1:{}", &OWNER[2..])), (-1, raw(OWNER).1));
    for s in ["1:00", &format!("5:{}", &OWNER[2..]), &OWNER[2..], &format!("{OWNER}0"), "EQAAAA"] {
        assert_eq!(scaas_rpc::ton::raw_address(s), None, "{s}");
    }
    assert_eq!(scaas_rpc::ton::format_raw(raw(OWNER)), OWNER.to_lowercase());
}

// ---------------------------------------------------------------- the BoC reader

/// A BoC of `cells` (each `(d2 bits descriptor-free data, refs)`, in order, cell 0 the root), size 2, offsets 4, no index,
/// no CRC.
fn boc_of(cells: &[(Vec<u8>, Vec<u16>)]) -> Vec<u8> {
    let mut body = Vec::new();
    for (data, refs) in cells {
        body.push(refs.len() as u8);
        body.push((data.len() * 2) as u8);
        body.extend(data);
        for r in refs {
            body.extend(r.to_be_bytes());
        }
    }
    let mut b = vec![0xb5, 0xee, 0x9c, 0x72, 0x02, 0x04];
    b.extend((cells.len() as u16).to_be_bytes());
    b.extend(1u16.to_be_bytes());
    b.extend(0u16.to_be_bytes());
    b.extend((body.len() as u32).to_be_bytes());
    b.extend(0u16.to_be_bytes());
    b.extend(body);
    b
}

/// A chain of `n` cells, each referring to the next: depth `n - 1`.
fn chain(n: usize) -> Vec<u8> {
    boc_of(&(0..n).map(|i| (vec![1], if i + 1 < n { vec![(i + 1) as u16] } else { vec![] })).collect::<Vec<_>>())
}

/// Depth: TON's own limit of 1024 is read, 1025 refused (computed without recursion).
#[test]
fn a_boc_deeper_than_1024_is_refused() {
    assert!(boc::parse(&chain(1025)).is_ok(), "depth 1024");
    assert!(boc::parse(&chain(1026)).is_err(), "depth 1025");
}

/// Length: at most 4096 cells; the cells' size field must match; no byte after the cells (or after the CRC); a reference
/// to an earlier cell (a cycle), past the last cell or a fifth reference; a cell with a level; another magic. Each refused,
/// each beside its control.
#[test]
fn a_boc_out_of_bounds_is_refused() {
    let one = |data: Vec<u8>| boc_of(&[(data, vec![])]);
    assert!(boc::parse(&one(vec![7])).is_ok(), "control");
    let many = boc_of(&vec![(vec![], vec![]); 4096]);
    assert!(boc::parse(&many).is_ok(), "4096 cells");
    assert!(boc::parse(&boc_of(&vec![(vec![], vec![]); 4097])).is_err(), "4097 cells");
    let mut b = one(vec![7]);
    b.push(0);
    assert!(boc::parse(&b).is_err(), "a byte after the cells");
    let mut b = one(vec![7]);
    b[15] += 1;
    assert!(boc::parse(&b).is_err(), "a cells size past the cells");
    assert!(boc::parse(&boc_of(&[(vec![], vec![1]), (vec![], vec![1])])).is_err(), "a reference to itself");
    assert!(boc::parse(&boc_of(&[(vec![], vec![1]), (vec![], vec![])])).is_ok(), "control: a reference forward");
    assert!(boc::parse(&boc_of(&[(vec![], vec![2]), (vec![], vec![])])).is_err(), "a reference past the last cell");
    let five = boc_of(&[(vec![], vec![1; 5]), (vec![], vec![])]);
    assert!(boc::parse(&five).is_err(), "five references");
    let four = boc_of(&[(vec![], vec![1; 4]), (vec![], vec![])]);
    assert!(boc::parse(&four).is_ok(), "control: four references");
    let mut b = one(vec![7]);
    b[18] |= 0x20;
    assert!(boc::parse(&b).is_err(), "a cell with a level");
    let mut b = one(vec![7]);
    b[0] = 0x68;
    assert!(boc::parse(&b).is_err(), "another magic");
    assert!(boc::parse(&b[..3]).is_err(), "truncated");
}

/// A cell's bits: a padded length (odd descriptor) has its completion tag stripped; a padded last byte of 0 is refused.
#[test]
fn a_cells_bits_follow_the_completion_tag() {
    let mut b = boc_of(&[(vec![0xff, 0b1010_1000], vec![])]);
    b[19] = 3; // d2 odd: one full byte and one padded
    let c = boc::parse(&b).unwrap();
    assert_eq!((c.bits, c.data.clone()), (12, vec![0xff, 0b1010_0000]));
    b[21] = 0;
    assert!(boc::parse(&b).is_err(), "a padded byte without its tag");
}

/// `std_address` reads exactly an `addr_std` without anycast: 267 bits, no reference; `address_slice` writes one.
#[test]
fn std_addresses_round_trip_and_nothing_else_is_one() {
    let (wc, h) = raw(MASTER);
    let s = boc::address_slice(wc, &h);
    assert_eq!(boc::std_address(&boc::parse(&s).unwrap()), Some((wc, h)));
    assert_eq!(boc::std_address(&boc::parse(&boc::address_slice(-1, &h)).unwrap()), Some((-1, h)));
    // the first byte holds the tag `10` and the anycast bit: `11` (addr_var) and an anycast are no addr_std
    for (why, first) in [("addr_var", 0xc0u8), ("anycast", 0xa0)] {
        let mut b = s.clone();
        let at = b.len() - 34;
        b[at] = (b[at] & 0x1f) | first;
        assert_eq!(boc::std_address(&boc::parse(&b).unwrap()), None, "{why}");
    }
    // the same 267 bits with a reference
    let mut b = boc_of(&[(s[s.len() - 34..].to_vec(), vec![1]), (vec![], vec![])]);
    b[19] = 67;
    let c = boc::parse(&b).unwrap();
    assert_eq!((c.bits, c.refs.len()), (267, 1));
    assert_eq!(boc::std_address(&c), None, "a cell with a reference");
}
