// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! ua-rs-sign T15m (ARCH-POS-13; spec no-decryption-oracle §4.2 R1–R7, §4.12): `pqz-read`, the PQZ reference reading layer.
//! Without a node: the holder's configuration is required before any request goes out. Against a local `anvil` (`ANVIL`,
//! default `anvil` on the PATH; `--ignored`, under `scripts/capped`; the anvil is killed when the test ends): PQZ state
//! written into storage and code with `anvil_setStorageAt` / `anvil_setCode` from three sources: the forge rows
//! (`state.json`, `PqzStateVectors.t.sol`: the words the tool reads equal the contract's byte for byte), the wallet rows
//! (`wallet_state.json`: real `pq_kat` keys decrypt their balances, the positive control; group 3g: a key version 1 read by
//! `--key-version`) and `tests/pqz_chain` (an audited op 1 to a real auditor key, a pending window past `INLINE_MAX`, a PQZH
//! twin). Each refusal of R2, R3, R5 and R6 named.
//! The default set only (the rows' set). UNAUDITED.
#![cfg_attr(feature = "vectors", allow(dead_code, unused_imports))]
mod pqz_chain;

use pqz_chain::{forge_versions, h, hx, merge, Chain};
use pqz_ffi::stmt::{self as st, Word};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};

const CLI: &str = env!("CARGO_BIN_EXE_pqz-read");
const SET: &str = "n2304-kmax4096";

fn path(rel: &str) -> String {
    format!("{}/../../{rel}", env!("CARGO_MANIFEST_DIR"))
}
fn load(rel: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path(rel)).unwrap()).unwrap()
}

/// `pq_kat`'s `pqz_key(0, index)` as the tool's stdin JSON.
fn kat(index: u32) -> Value {
    let keys = load("smartcontracts/vectors/ua/keys.json");
    let m = keys["mnemonics"].as_array().unwrap().iter().find(|m| m["id"] == "pq_kat").unwrap();
    json!({"mnemonic": m["words"], "passphrase": m["passphrase"], "account": 0, "index": index})
}

/// The tool on `args`, `key` on its stdin (none: stdin closed).
fn cli(args: &[String], key: Option<&Value>) -> Result<Value, String> {
    let mut child = Command::new(CLI).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    if let Some(k) = key {
        // a refusal before stdin is read breaks the pipe; the exit status carries the verdict
        let _ = stdin.write_all(k.to_string().as_bytes());
    }
    drop(stdin);
    let out = child.wait_with_output().unwrap();
    if out.status.success() {
        Ok(serde_json::from_slice(&out.stdout).unwrap())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).into_owned())
    }
}

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

/// R1–R6: no request goes out without the holder's configuration (the URL's port is closed again, so a build that sent one
/// fails fast); the command's own fields; no key needed to refuse.
#[test]
fn the_holders_configuration_is_required() {
    let url = format!("http://{}", std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap());
    let (a20, a32) = ("0x00000000000000000000000000000000000000aa", format!("0x{}", "ab".repeat(32)));
    let full = s(&["--rpc", &url, "--chain-id", "31337", "--chain-uid", &a32, "--factory", a20, "--registry", a20, "--token", a20, "--ua",
        &a32, "--depth", "1", "--key-version", "0", "--for-op7", "false"]);
    for missing in ["--rpc", "--chain-id", "--chain-uid", "--factory", "--registry", "--token", "--ua", "--depth"] {
        let mut a = full.clone();
        let i = a.iter().position(|x| x == missing).unwrap();
        a.drain(i..i + 2);
        assert!(cli(&a, None).unwrap_err().contains("needs --rpc"), "{missing}");
    }
    let mut both = full.clone();
    both.push("--finalized".into());
    assert!(cli(&both, None).unwrap_err().contains("needs --rpc"), "one of --depth / --finalized");
    let without_op7 = full[..full.len() - 2].to_vec();
    assert!(cli(&without_op7, None).unwrap_err().contains("--for-op7"), "balance: --for-op7 named, no default");
    let without_version = [&full[..full.len() - 4], &full[full.len() - 2..]].concat();
    assert!(cli(&without_version, None).unwrap_err().contains("--key-version"), "balance: --key-version named, no default (group 3g)");
    let mut audit = without_op7.clone();
    audit.extend(s(&["--command", "auditRead", "--from-ua", &a32, "--send-counter", "0"]));
    assert!(cli(&audit, None).unwrap_err().contains("auditRead needs"), "auditRead: the entry's three fields");
    let mut other = without_op7.clone();
    other.extend(s(&["--command", "dec"]));
    assert!(cli(&other, None).unwrap_err().contains("balance or auditRead"), "no other command");
    let mut twice = full.clone();
    twice.extend(s(&["--token", a20]));
    assert!(cli(&twice, None).unwrap_err().contains("given twice"), "one value each");
    // R1 (owner 2026-11-08): `--rpc` once or more, each a distinct node the holder names; the same node twice is refused
    let mut nodes = full.clone();
    nodes.extend(s(&["--rpc", "http://127.0.0.1:1", "--rpc-agree"]));
    assert!(cli(&nodes, None).unwrap_err().contains("key JSON"), "a second node and --rpc-agree accepted, before any request");
    let mut same = full.clone();
    same.extend(s(&["--rpc", &url]));
    assert!(cli(&same, None).unwrap_err().contains("the same node twice"), "one node named twice");
    assert!(cli(&full, None).unwrap_err().contains("key JSON"), "the key on stdin, before any request");
    if cfg!(feature = "vectors") {
        // T15c2: a `vectors` build (never a release) makes no key handle without the test-only marker, before any request
        assert!(cli(&full, Some(&kat(0))).unwrap_err().contains("the key: Argument"), "a vectors build");
    }
}

// ------------------------------------------------------------------------------------------------------------------------------
// the anvil fixture
// ------------------------------------------------------------------------------------------------------------------------------

fn rpc(url: &str, method: &str, params: Value) -> Value {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string();
    let out = Command::new("curl").args(["-s", "-X", "POST", "-H", "content-type: application/json", "--data-binary", "@-", url])
        .stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().and_then(|mut c| {
            c.stdin.take().unwrap().write_all(body.as_bytes())?;
            c.wait_with_output()
        }).unwrap();
    serde_json::from_slice::<Value>(&out.stdout).map(|v| v["result"].clone()).unwrap_or(Value::Null)
}

/// Stops the local anvil when the test ends, whatever the outcome.
struct Anvil(std::process::Child);
impl Drop for Anvil {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn add(a: &Word, i: u64) -> Word {
    let mut o = *a;
    let mut c = u128::from(i);
    for b in o.iter_mut().rev() {
        let t = u128::from(*b) + (c & 0xff);
        *b = t as u8;
        c = (c >> 8) + (t >> 8);
    }
    o
}
fn be(n: u64) -> Word {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&n.to_be_bytes());
    w
}
fn k(a: &[u8], b: &[u8]) -> Word {
    scaas_ua::keccak256(&[a, b].concat())
}
fn w32(v: &Value) -> Word {
    h(v).try_into().unwrap()
}
fn a20(v: &str) -> [u8; 20] {
    h(&json!(v)).try_into().unwrap()
}
fn word_of(a: &[u8; 20]) -> Word {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}

/// The registry's slot of `UAStore.Layout` field `field`, read from its layout pin (ua-mtx-merge's
/// `smartcontracts/evm/test/ua/UAStoreLayout.t.sol`: the probe writes one field per slot, `s.<field>…; // <slot>`), never copied
/// by hand (T20b).
fn reg_slot(field: &str) -> u64 {
    let pin = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../smartcontracts/evm/test/ua/UAStoreLayout.t.sol")).unwrap();
    pin.lines()
        .find_map(|l| {
            let rest = l.trim().strip_prefix("s.")?.strip_prefix(field)?;
            rest.starts_with(['[', '.', ' ']).then_some(())?;
            rest.rsplit_once("// ")?.1.split_whitespace().next()?.parse().ok()
        })
        .unwrap_or_else(|| panic!("{field}: not in the registry's layout pin"))
}

/// `OpenFactory._rec`'s slot, read from the pin ua-mtx-merge keeps for it (`test/zether/ZetherStateVectors.t.sol`, `REC`; T20b
/// second sync), never copied by hand.
fn rec_slot() -> u64 {
    let pin = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../smartcontracts/evm/test/zether/ZetherStateVectors.t.sol"))
        .unwrap();
    pin.lines().find_map(|l| l.trim().strip_prefix("uint256 internal constant REC = ")?.strip_suffix(';')?.parse().ok()).expect("REC")
}

struct Node {
    url: String,
    root: Word,
    chain_id: u64,
    uid: Word,
}

impl Node {
    fn set(&self, addr: &[u8; 20], slot: &Word, w: &Word) {
        assert_eq!(rpc(&self.url, "anvil_setStorageAt", json!([hx(addr), hx(slot), hx(w)])), json!(true));
    }
    fn code(&self, addr: &[u8; 20], code: &Value) {
        rpc(&self.url, "anvil_setCode", json!([hx(addr), code]));
        assert_eq!(&rpc(&self.url, "eth_getCode", json!([hx(addr), "latest"])), code);
    }
    /// `OpenFactory._rec[token]` (the factory index, ua-mtx-merge T67; its slot from the layout pin): word 2, from the low end
    /// `contractClass(16) ‖ kind(16) ‖ version(64)`; `exists` is class TOKEN (1), else 0 (not made here).
    fn catalogue(&self, factory: &[u8; 20], token: &[u8; 20], kind: u8, exists: bool) {
        let mut w = [0u8; 32];
        w[31] = exists as u8;
        w[29] = kind;
        w[27] = 1; // version 1
        self.set(factory, &add(&k(&word_of(token), &be(rec_slot())), 2), &w);
    }
    /// `token`'s code: a clone of a chain-neutral release (the EIP-1167 proxy of `implementation` with its `ChainEnv` appended;
    /// chain-neutral spec §2, the layout `create3_kat.json` pins), its env naming `registry` (owner 2026-11-08: the reader checks
    /// `--registry` against it).
    fn clone_of(&self, token: &[u8; 20], registry: &[u8; 20]) {
        use scaas_ua::factory::{clone_runtime, ChainEnv};
        let env = ChainEnv { chain_uid: self.uid, registry: *registry, gov_router: [0x33; 20], smart_key_account_impl: [0x44; 20],
            hedera: false, deps: vec![[0x55; 20]], params: vec![] };
        self.code(token, &json!(hx(&clone_runtime(&[0x11; 20], &env))));
    }
    /// A words request's account (`balance`'s shape: the forge rows with [`forge_versions`], the wallet rows, `Chain::bal`)
    /// into `token`'s storage at its key version (group 3g: `acct[ua][v]`, `sendCounter[ua]`), its key record and version word
    /// into `registry`'s (`pqzKey[ua][v]`, `pqzVersions[ua]`), its codes.
    fn account(&self, token: &[u8; 20], registry: &[u8; 20], psid: &Value, r: &Value) {
        let (ua, v) = (w32(&r["ua"]), be(r["keyVersion"].as_u64().unwrap()));
        self.set(token, &add(&self.root, 2), &w32(psid));
        let base = k(&v, &k(&ua, &add(&self.root, 8)));
        for (i, w) in r["account"].as_array().unwrap().iter().enumerate() {
            self.set(token, &add(&base, i as u64), &w32(w));
        }
        for e in r["pending"].as_array().unwrap() {
            self.set(token, &k(&be(e["index"].as_u64().unwrap()), &add(&base, 3)), &w32(&e["word"]));
        }
        for (i, w) in r["accWords"].as_array().unwrap().iter().enumerate() {
            self.set(token, &add(&base, 4 + i as u64), &w32(w));
        }
        self.set(token, &k(&ua, &add(&self.root, 12)), &w32(&r["sendCounterWord"]));
        self.set(registry, &k(&v, &k(&ua, &be(reg_slot("pqzKey")))), &w32(&r["keyRecord"]));
        self.set(registry, &k(&ua, &be(reg_slot("pqzVersions"))), &w32(&r["keyVersions"]));
        for b in r["blobs"].as_array().unwrap() {
            self.code(&a20(b["address"].as_str().unwrap()), &b["code"]);
        }
    }
    /// `PqzCore.entryRefOf` on this chain.
    fn entry_ref(&self, token: &[u8; 20], from: &Word, counter: u64) -> Word {
        let tag = scaas_ua::keccak256(b"SCAAS-PQZ-ENTRY-V1");
        scaas_ua::keccak256(&[tag, be(self.chain_id), self.uid, word_of(token), *from, be(counter)].concat())
    }
    /// An entry's pointer (at this chain's `entryRef`) and code; the token's auditor words and the auditor's key record.
    fn entry(&self, token: &[u8; 20], registry: &[u8; 20], from: &Word, counter: u64, blob: &Value, aud: &Value) {
        let ptr = a20(blob["address"].as_str().unwrap());
        self.set(token, &k(&self.entry_ref(token, from, counter), &add(&self.root, 9)), &word_of(&ptr));
        self.code(&ptr, &blob["code"]);
        self.set(token, &self.root, &w32(&aud["auditorMode"]));
        self.set(token, &add(&self.root, 7), &w32(&aud["auditorUA"]));
        self.set(registry, &k(&be(0), &k(&w32(&aud["auditorUA"]), &be(reg_slot("pqzKey")))), &w32(&aud["keyRecord"])); // the auditor's version 0
        self.code(&a20(aud["key"]["address"].as_str().unwrap()), &aud["key"]["code"]);
    }
}

/// A node in front of `upstream` (R1, owner 2026-11-08): each answer passes `f(method, params, result, i)`, `i` this node's
/// request number from 1; `None` drops the connection (a node that fails). `hits` counts the requests it received.
fn node(upstream: String, hits: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    f: impl Fn(&str, &Value, Value, usize) -> Option<Value> + Send + 'static) -> String {
    use std::io::{BufRead, BufReader, Read, Write};
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            let mut r = BufReader::new(c.try_clone().unwrap());
            let mut len = 0usize;
            loop {
                let mut line = String::new();
                if r.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap();
                }
            }
            let mut body = vec![0u8; len];
            if r.read_exact(&mut body).is_err() {
                continue;
            }
            let req: Value = serde_json::from_slice(&body).unwrap();
            let i = hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            let res = rpc(&upstream, req["method"].as_str().unwrap(), req["params"].clone());
            if let Some(res) = f(req["method"].as_str().unwrap(), &req["params"], res, i) {
                let out = json!({"jsonrpc": "2.0", "id": 1, "result": res}).to_string();
                let _ = write!(c, "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{out}", out.len());
            }
        }
    });
    url
}

/// A one-connection-at-a-time JSON-RPC proxy in front of `upstream` that lies about the read block (R3): `number` answers the
/// first non-genesis `eth_getBlockByNumber` with the next block's number, `hash` the second one with another hash, `hash4` the
/// fourth (T15n: `decoys`' re-check of its sync block).
fn liar(upstream: String, mode: &'static str) -> String {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    std::thread::spawn(move || {
        let mut n = 0;
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            let mut r = BufReader::new(c.try_clone().unwrap());
            let mut len = 0usize;
            loop {
                let mut line = String::new();
                if r.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap();
                }
            }
            let mut body = vec![0u8; len];
            r.read_exact(&mut body).unwrap();
            let req: Value = serde_json::from_slice(&body).unwrap();
            let mut res = rpc(&upstream, req["method"].as_str().unwrap(), req["params"].clone());
            if req["method"] == "eth_getBlockByNumber" && req["params"][0] != "0x0" {
                n += 1;
                if mode == "number" && n == 1 {
                    let num = u64::from_str_radix(res["number"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
                    res["number"] = json!(format!("0x{:x}", num + 1));
                }
                if (mode == "hash" && n == 2) || (mode == "hash4" && n == 4) {
                    res["hash"] = json!(hx(&[0x5a; 32]));
                }
            }
            let out = json!({"jsonrpc": "2.0", "id": 1, "result": res}).to_string();
            let _ = write!(c, "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{out}", out.len());
        }
    });
    url
}

const FACTORY: &str = "0x00000000000000000000000000000000000fac70";
const ZETHER_TOKEN: &str = "0x0000000000000000000000000000000000002e7a";
const UNLISTED: &str = "0x0000000000000000000000000000000000002e7b";
const NOT_EXISTS: &str = "0x0000000000000000000000000000000000002e7c";
const WALLET_REG: &str = "0x2222222222222222222222222222222222222222";
const CW_TOKEN: &str = "0x00000000000000000000000000000000000c0de1";
const CW_PQZH: &str = "0x00000000000000000000000000000000000c0de2";
const CW_REG: &str = "0x00000000000000000000000000000000000c0de3";
const NO_CODE: &str = "0x00000000000000000000000000000000000c0de4";
const BARE_PROXY: &str = "0x00000000000000000000000000000000000c0de5";

/// `pqz-read` against a local `anvil`: R2, R3 (the block of `head − depth` by hash, a node that answers another block or whose
/// block changes during the read), R5 (uncatalogued, not `exists`, a Zether kind), R6 (another key, not the auditor, no
/// auditor), the words byte for byte against the forge rows (`balance` of five accounts, one with a materialised `acc`;
/// `auditRead`'s entry and auditor words), real balances and an audited amount decrypted by `pq_kat` keys, the pending window
/// at `INLINE_MAX` and `INLINE_MAX_PQZH`.
#[cfg(not(feature = "vectors"))] // a `vectors` build makes no key handle without the test-only marker (T15c2)
#[test]
#[ignore]
fn reading_layer_against_anvil() {
    if st::SET != SET {
        return;
    }
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{port}");
    let bin = std::env::var("ANVIL").unwrap_or_else(|_| "anvil".into());
    let _anvil = Anvil(Command::new(bin).args(["--port", &port.to_string(), "--silent"]).stdout(Stdio::null()).spawn().unwrap());
    let mut up = false;
    for _ in 0..100 {
        if rpc(&url, "eth_chainId", json!([])).is_string() {
            up = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(up, "anvil did not start");
    let chain_id = u64::from_str_radix(rpc(&url, "eth_chainId", json!([])).as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    let genesis = rpc(&url, "eth_getBlockByNumber", json!(["0x0", false]))["hash"].as_str().unwrap().to_string();
    let forge = load(&format!("smartcontracts/vectors/pqz/{SET}/state.json"));
    let n = Node { url: url.clone(), root: w32(&forge["layout"]["root"]), chain_id, uid: w32(&json!(genesis)) };
    let factory = a20(FACTORY);

    // the forge rows: five accounts and the audited op 1 entry, at the rows' token and registry
    let (ft, fr) = (a20(forge["token"].as_str().unwrap()), a20(forge["registry"].as_str().unwrap()));
    n.catalogue(&factory, &ft, 4, true);
    n.clone_of(&ft, &fr);
    for a in forge["accounts"].as_array().unwrap() {
        n.account(&ft, &fr, &forge["psid"], &merge(a.clone(), forge_versions(a)));
    }
    let fe = forge["entries"].as_array().unwrap().iter().find(|e| e["name"] == "op1 carol->alice audited").unwrap();
    let faud = json!({"auditorMode": forge["auditorMode"], "auditorUA": forge["auditorUA"], "keyRecord": forge["auditorKeyRecord"],
        "key": forge["auditorKey"]});
    n.entry(&ft, &fr, &w32(&fe["fromUA"]), fe["sendCounter"].as_u64().unwrap(), &fe["blob"], &faud);

    // the wallet rows: A (acc a reference into op 1's blob, 750) and B (a pending credit and a TRIVIAL entry, 257)
    let wallet = load(&format!("smartcontracts/vectors/pqz/{SET}/wallet_state.json"));
    let rows = wallet["rows"].as_array().unwrap();
    let wt = a20(rows[0]["request"]["token"].as_str().unwrap());
    n.catalogue(&factory, &wt, 12, true);
    n.clone_of(&wt, &a20(WALLET_REG));
    for r in rows {
        n.account(&wt, &a20(WALLET_REG), &r["request"]["psid"], &r["request"]);
    }

    // tests/pqz_chain with pq_kat keys: A shields 1,000 and pays B 250 audited (AUD = pqz_key(0, 2)); B then shields 1 seventeen
    // times (18 pending: the window [0, 16) at INLINE_MAX, [0, 10) at INLINE_MAX_PQZH)
    let w = {
        let m = &kat(0);
        scaas_ua::wallet::Wallet::from_mnemonic(m["mnemonic"].as_str().unwrap(), m["passphrase"].as_str().unwrap()).unwrap()
    };
    let (ua_a, ua_b, ua_aud): (Word, Word, Word) = ([0xA1; 32], [0xB0; 32], [0xAD; 32]);
    let keys: Vec<_> = (0..3).map(|i| w.pqz_key(0, i).unwrap()).collect();
    let mut c = Chain::new();
    for _ in 0..16 {
        c.put(Vec::new()); // past the wallet rows' SSTORE2 addresses (the same generator), so no code is overwritten
    }
    for (ua, key) in [ua_a, ua_b, ua_aud].iter().zip(&keys) {
        c.register(*ua, &key.pk());
    }
    c.auditor = Some(ua_aud);
    c.shield(&ua_a, 1000);
    let req = merge(merge(c.own(&ua_a, 16), c.debit_fields()),
        json!({"toUA": hx(&ua_b), "pkT": hx(&keys[1].pk()), "pkA": hx(&keys[2].pk()), "amount": 250, "mode": "BUNDLE"}));
    let p: Value = serde_json::from_str(&keys[0].call("proveTransfer", req.to_string().as_bytes()).unwrap()).unwrap();
    let stmt = h(&p["stmt"]);
    assert_eq!(pqz_ffi::precompile(&st::input(1, &stmt, &h(&p["proof"]))), Ok(pqz_ffi::VALID), "op 1 verifies");
    let er = c.settle1(&stmt, None);
    for _ in 0..17 {
        c.shield(&ua_b, 1);
    }
    let (cw, cwh, creg) = (a20(CW_TOKEN), a20(CW_PQZH), a20(CW_REG));
    n.catalogue(&factory, &cw, 5, true);
    n.catalogue(&factory, &cwh, 13, true);
    n.clone_of(&cw, &creg);
    n.clone_of(&cwh, &creg);
    // catalogued PQZ tokens whose code is no clone with an env (owner 2026-11-08): none, and the bare proxy
    n.catalogue(&factory, &a20(NO_CODE), 4, true);
    n.catalogue(&factory, &a20(BARE_PROXY), 4, true);
    n.code(&a20(BARE_PROXY), &json!(hx(&scaas_ua::factory::clone_runtime(&[0x11; 20], &scaas_ua::factory::ChainEnv {
        chain_uid: n.uid, registry: a20(WALLET_REG), gov_router: [0; 20], smart_key_account_impl: [0; 20], hedera: false, deps: vec![],
        params: vec![] })[..45])));
    for ua in [ua_a, ua_b] {
        let full = c.own(&ua, 1 << 20); // every pending slot, so the tool's window is its own
        n.account(&cw, &creg, &json!(hx(&st::PQZL_ID)), &full);
        n.account(&cwh, &creg, &json!(hx(&st::PQZH_ID)), &full);
    }
    let ent = &c.entries[&er];
    let aud_ptr = c.key_ptr(&ua_aud);
    let cw_aud = merge(c.auditor_words(1), json!({"keyRecord": hx(&c.key_record(&ua_aud)),
        "key": {"address": hx(&aud_ptr), "code": hx(&c.blobs[&aud_ptr])}}));
    n.entry(&cw, &creg, &ent.from, ent.ctr, &json!({"address": hx(&ent.ptr), "code": hx(&c.blobs[&ent.ptr])}), &cw_aud);

    // the zether-kind and the unlisted tokens (R5)
    n.catalogue(&factory, &a20(ZETHER_TOKEN), 2, true);
    n.catalogue(&factory, &a20(NOT_EXISTS), 4, false);
    rpc(&url, "anvil_mine", json!(["0x3"]));
    // the head's state, which a read at depth 2 must not see: another psid on the wallet token, no auditor on the chain one
    n.set(&wt, &add(&n.root, 2), &[0x5a; 32]);
    let mut none = w32(&c.auditor_words(1)["auditorMode"]);
    none[10] = 0;
    n.set(&cw, &n.root, &none);
    rpc(&url, "anvil_mine", json!(["0x1"]));

    let cid = chain_id.to_string();
    let base = |rpc_url: &str, chain: &str, uid: &str, token: &str, reg: &str, ua: &str, depth: &str| {
        s(&["--rpc", rpc_url, "--chain-id", chain, "--chain-uid", uid, "--factory", FACTORY, "--registry", reg, "--token", token,
            "--ua", ua, "--depth", depth])
    };
    let on = |token: &str, reg: &str, ua: &str| base(&url, &cid, &genesis, token, reg, ua, "2");
    let balv = |mut a: Vec<String>, version: u64, op7: bool| {
        a.extend(s(&["--key-version", &version.to_string(), "--for-op7", if op7 { "true" } else { "false" }]));
        a
    };
    let bal = |a: Vec<String>, op7: bool| balv(a, 0, op7);
    let words = |mut a: Vec<String>| {
        a.push("--words".into());
        cli(&a, None).unwrap()
    };

    // the words of every forge account, byte for byte (R4: the pinned layout; the facade's window)
    let (ft_s, fr_s) = (forge["token"].as_str().unwrap(), forge["registry"].as_str().unwrap());
    for a in forge["accounts"].as_array().unwrap() {
        let out = words(bal(on(ft_s, fr_s, a["ua"].as_str().unwrap()), false));
        let r = &out["request"];
        for f in ["account", "pending", "accWords", "blobs", "keyRecord"] {
            assert_eq!(r[f], a[f], "{}: {f}", a["name"]);
        }
        let fv = forge_versions(a);
        for f in ["sendCounterWord", "keyVersion", "keyVersions"] {
            assert_eq!(r[f], fv[f], "{}: {f}", a["name"]);
        }
        assert_eq!((&r["psid"], &r["ua"], &r["forOp7"]), (&forge["psid"], &a["ua"], &json!(false)), "{}", a["name"]);
    }
    assert!(forge["accounts"].as_array().unwrap().iter().any(|a| !a["accWords"].as_array().unwrap().is_empty()), "a materialised acc");
    // auditRead's words of the forge entry
    let mut ar = on(ft_s, fr_s, forge["auditorUA"].as_str().unwrap());
    ar.extend(s(&["--command", "auditRead", "--key-version", "0", "--from-ua", fe["fromUA"].as_str().unwrap(), "--send-counter", &fe["sendCounter"].to_string(),
        "--leg", "0"]));
    let r = words(ar.clone())["request"].clone();
    assert_eq!((&r["entryPtr"], &r["auditorMode"], &r["auditorUA"], &r["keyRecord"]),
        (&fe["entryPtr"], &forge["auditorMode"], &forge["auditorUA"], &forge["auditorKeyRecord"]));
    assert_eq!(r["blobs"], json!([fe["blob"], forge["auditorKey"]]));
    let ftw = word_of(&ft);
    assert_eq!(r["entryRef"], json!(hx(&n.entry_ref(&ft, &w32(&fe["fromUA"]), fe["sendCounter"].as_u64().unwrap()))));
    assert_eq!((&r["chainId"], &r["chainUid"], &r["token"]), (&json!(chain_id), &json!(genesis), &json!(hx(&ftw[12..]))));

    // the positive control: the wallet rows' balances with their own keys, each at its key version (group 3g: A's version 1
    // is `pqz_key_version(0, 0, 1)` on `acct[A][1]`, its version 0 the stale rest)
    let wt_s = rows[0]["request"]["token"].as_str().unwrap();
    for r in rows {
        let (i, v) = (r["index"].as_u64().unwrap() as u32, r["version"].as_u64().unwrap());
        let out = cli(&balv(on(wt_s, WALLET_REG, r["request"]["ua"].as_str().unwrap()), v, false), Some(&kat(i))).unwrap();
        assert_eq!(out["value"], r["value"], "{}", r["name"]);
        assert!(out["block"].is_u64() && out["blockHash"].is_string());
    }
    assert!(rows.iter().any(|r| r["version"] == 1), "a version-1 row");
    let w2 = cli(&balv(on(wt_s, WALLET_REG, rows[0]["request"]["ua"].as_str().unwrap()), 2, false), Some(&kat(0))).unwrap_err();
    assert!(w2.contains("R6"), "a version the registry does not hold: {w2}");
    // R3: the head's state is not read at depth 2, and is at depth 0 (positive control)
    let ua_wa = rows[0]["request"]["ua"].as_str().unwrap();
    let head = |mut a: Vec<String>| {
        let i = a.iter().position(|x| x == "--depth").unwrap();
        a[i + 1] = "0".into();
        a
    };
    assert_eq!(words(bal(on(wt_s, WALLET_REG, ua_wa), false))["request"]["psid"], rows[0]["request"]["psid"], "depth 2");
    assert_eq!(words(head(bal(on(wt_s, WALLET_REG, ua_wa), false)))["request"]["psid"], json!(hx(&[0x5a; 32])), "the head");

    // tests/pqz_chain: A 750 (acc the reference), B's window, the audited amount on the auditor's key
    let (sa, sb, saud) = (hx(&ua_a), hx(&ua_b), hx(&ua_aud));
    let v = |a: Vec<String>, i: u32| cli(&a, Some(&kat(i))).unwrap();
    assert_eq!(v(bal(on(CW_TOKEN, CW_REG, &sa), false), 0)["value"], json!(750));
    assert_eq!(v(bal(on(CW_TOKEN, CW_REG, &sb), false), 1)["value"], json!(250 + 15), "INLINE_MAX: the credit and 15 of 17");
    assert_eq!(v(bal(on(CW_TOKEN, CW_REG, &sb), true), 1)["value"], json!(250 + 15), "op 7 on a PQZL token: INLINE_MAX");
    assert_eq!(v(bal(on(CW_PQZH, CW_REG, &sb), true), 1)["value"], json!(250 + 9), "op 7 on a PQZH token: INLINE_MAX_PQZH");
    assert_eq!(v(bal(on(CW_PQZH, CW_REG, &sb), false), 1)["value"], json!(250 + 15), "op 1 on a PQZH token: INLINE_MAX");
    let audit = |a: Vec<String>, from: &str, ctr: &str| {
        let mut a = a;
        a.extend(s(&["--command", "auditRead", "--key-version", "0", "--from-ua", from, "--send-counter", ctr, "--leg", "0"]));
        a
    };
    let out = v(audit(on(CW_TOKEN, CW_REG, &saud), &sa, "0"), 2);
    assert_eq!(out["amount"], json!(250), "the audited amount on the auditor's key");

    // the refusals, each named
    let no = |a: Vec<String>, key: Option<u32>, want: &str| {
        let k = key.map(kat);
        let e = cli(&a, k.as_ref()).unwrap_err();
        assert!(e.contains(want), "want {want}: {e}");
    };
    let wa = || bal(on(wt_s, WALLET_REG, ua_wa), false);
    no(bal(base(&url, "1", &genesis, wt_s, WALLET_REG, ua_wa, "2"), false), Some(0), "R2: eth_chainId");
    no(bal(base(&url, &cid, &hx(&[0x24; 32]), wt_s, WALLET_REG, ua_wa, "2"), false), Some(0), "R2: the genesis hash");
    no(bal(base(&url, &cid, &genesis, wt_s, WALLET_REG, ua_wa, "100"), false), Some(0), "R3: the chain is shorter");
    no(bal(base(&liar(url.clone(), "number"), &cid, &genesis, wt_s, WALLET_REG, ua_wa, "2"), false), Some(0), "R3: the node answered another block");
    no(bal(base(&liar(url.clone(), "hash"), &cid, &genesis, wt_s, WALLET_REG, ua_wa, "2"), false), Some(0), "R3: the block changed");
    assert_eq!(cli(&bal(base(&liar(url.clone(), "none"), &cid, &genesis, wt_s, WALLET_REG, ua_wa, "2"), false), Some(&kat(0))).unwrap()["value"],
        rows[0]["value"], "the proxy alone changes nothing (positive control)");
    for t in [UNLISTED, NOT_EXISTS, ZETHER_TOKEN] {
        no(bal(on(t, WALLET_REG, ua_wa), false), Some(0), "R5: the token is not a PQZ token");
    }
    no(wa(), Some(1), "R6: the registry's PQZ key of --ua is not this key");
    // owner 2026-11-08: the token is a clone with a `ChainEnv`, and `--registry` is the registry it names
    for t in [NO_CODE, BARE_PROXY] {
        no(bal(on(t, WALLET_REG, ua_wa), false), Some(0), "R5: the token is not a clone of a chain-neutral release");
    }
    no(bal(on(wt_s, CW_REG, ua_wa), false), Some(0), "R6: --registry is not the token's registry");
    no(audit(on(CW_TOKEN, WALLET_REG, &saud), &sa, "0"), Some(2), "R6: --registry is not the token's registry");
    no(audit(on(CW_TOKEN, CW_REG, &sb), &sa, "0"), Some(1), "R6: --ua is not the token's auditor");
    no(audit(head(on(CW_TOKEN, CW_REG, &saud)), &sa, "0"), Some(2), "R6: --ua is not the token's auditor");
    no(audit(on(CW_TOKEN, CW_REG, &saud), &sa, "1"), Some(2), "no entry of --from-ua");
    no(audit(on(CW_TOKEN, CW_REG, &saud), &sa, "0"), Some(1), "R6: the registry's PQZ key");
    // ua-rs's own refusal after the reading layer's checks: the auditor reads a leg the entry does not have
    let mut leg1 = audit(on(CW_TOKEN, CW_REG, &saud), &sa, "0");
    *leg1.last_mut().unwrap() = "1".into();
    no(leg1, Some(2), "ua-rs refused the words: Argument");
    // R1 (owner 2026-11-08): several --rpc. Failover by default: a result's words are one node's, never a mix; `--rpc-agree`: a
    // strict majority of the named nodes returns the same complete read. The nodes are proxies of this anvil, each with its lie.
    use std::sync::{atomic::AtomicUsize, Arc};
    let ua_s = rows[0]["request"]["ua"].as_str().unwrap();
    let w0 = words(bal(on(wt_s, WALLET_REG, ua_s), false));
    let multi = |urls: &[&str], agree: bool| {
        let mut a: Vec<String> = urls.iter().flat_map(|u| s(&["--rpc", u])).collect();
        a.extend(s(&["--chain-id", &cid, "--chain-uid", &genesis, "--factory", FACTORY, "--registry", WALLET_REG, "--token", wt_s, "--ua",
            ua_s, "--depth", "2", "--key-version", "0", "--for-op7", "false", "--words"]));
        if agree {
            a.push("--rpc-agree".into());
        }
        cli(&a, None)
    };
    let hits = || Arc::new(AtomicUsize::new(0));
    let psid_slot = hx(&add(&n.root, 2));
    let lie = |byte: u8| {
        let slot = psid_slot.clone();
        move |m: &str, p: &Value, r: Value, _: usize| Some(if m == "eth_getStorageAt" && p[1] == json!(slot) { json!(hx(&[byte; 32])) } else { r })
    };
    let same = node(url.clone(), hits(), |_, _, r, _| Some(r));
    let (lie_a, lie_a2, lie_b) = (node(url.clone(), hits(), lie(0xa1)), node(url.clone(), hits(), lie(0xa1)), node(url.clone(), hits(), lie(0xb2)));
    let counted = hits();
    let unused = node(url.clone(), counted.clone(), lie(0xa1));
    // answers its first seven requests (R2, R3, R5, then the lying psid word), then fails
    let dies = {
        let l = lie(0xa1);
        node(url.clone(), hits(), move |m, p, r, i| if i <= 7 { l(m, p, r, i) } else { None })
    };
    let future = node(url.clone(), hits(), |m, _, r, _| Some(if m == "eth_blockNumber" { json!("0xffffff") } else { r }));
    let other_hash = node(url.clone(), hits(), |m, p, mut r, _| {
        if m == "eth_getBlockByNumber" && p[0] != "0x0" {
            r["hash"] = json!(hx(&[0x5a; 32]));
        }
        Some(r)
    });
    let blocks = hits();
    let late = {
        let b = blocks.clone();
        node(url.clone(), hits(), move |m, p, mut r, _| {
            if m == "eth_getBlockByNumber" && p[0] != "0x0" && b.fetch_add(1, std::sync::atomic::Ordering::SeqCst) >= 2 {
                r["hash"] = json!(hx(&[0x5b; 32])); // the read's own two looks pass, the one after every node's read does not
            }
            Some(r)
        })
    };
    let (dead, dead2) = ("http://127.0.0.1:1", "http://127.0.0.1:2");
    let req = |v: Result<Value, String>| v.unwrap()["request"].clone();
    // failover
    assert_eq!(req(multi(&[dead, &url], false)), w0["request"], "failover skips a dead first node");
    assert_eq!(req(multi(&[&url, &unused], false)), w0["request"], "the first node answered");
    assert_eq!(counted.load(std::sync::atomic::Ordering::SeqCst), 0, "a second node is not consulted when the first succeeds");
    assert_eq!(req(multi(&[&dies, &url], false)), w0["request"], "a node dying mid-read: the next re-reads everything, no mix");
    assert!(multi(&[dead, dead2], false).unwrap_err().contains("R1: no --rpc answered the whole read"), "all fail");
    assert!(multi(&[&url, &url], false).unwrap_err().contains("the same node twice"));
    assert_eq!(req(multi(&[&url], true)), w0["request"], "one node: --rpc-agree changes nothing");
    // --rpc-agree: a strict majority of the named nodes, each node over its whole read
    assert_eq!(req(multi(&[&lie_a, &url, &same], true)), w0["request"], "3 nodes, one differing word: the majority's words");
    assert_eq!(req(multi(&[dead, &url, &same], true)), w0["request"], "3 nodes, one dead");
    assert_eq!(multi(&[&url, &same, &future], true).unwrap()["block"], w0["block"], "a far-future block does not move the number");
    let refused = |urls: &[&str], what: &str| {
        let e = multi(urls, true).unwrap_err();
        assert!(e.contains("error: R1: no strict majority"), "{what}: {e}");
    };
    refused(&[&url, &lie_a, &lie_b], "3 nodes, all differing");
    refused(&[&url, &lie_a], "2 nodes differing");
    refused(&[&url, &same, &lie_a, &lie_a2], "4 nodes split 2-2");
    refused(&[&url, dead], "2 nodes, one dead");
    refused(&[&url, &other_hash], "a node answering another block hash");
    refused(&[&url, &late], "a node whose block changes after the reads (R3 after every node)");
}

// ------------------------------------------------------------------------------------------------------------------------------
// T15n: decoys (CTR-UA-29, owner 2026-11-07)
// ------------------------------------------------------------------------------------------------------------------------------

/// `--command decoys`'s own fields: only with `decoys`, `--count` named, `--decoy-filter` with `--window`, one of two filters.
#[test]
fn decoy_arguments() {
    let (a20, a32) = ("0x00000000000000000000000000000000000000aa", format!("0x{}", "ab".repeat(32)));
    let base = s(&["--rpc", "http://127.0.0.1:1", "--chain-id", "31337", "--chain-uid", &a32, "--factory", a20, "--registry", a20, "--token",
        a20, "--ua", &a32]);
    let with = |x: &[&str]| [base.clone(), s(x)].concat();
    for (args, want) in [
        (with(&["--depth", "0", "--for-op7", "false", "--count", "1"]), "go with --command decoys only"),
        (with(&["--depth", "0", "--command", "decoys"]), "decoys needs --count"),
        (with(&["--depth", "0", "--command", "decoys", "--count", "1", "--decoy-filter", "activity"]), "decoys needs --count"),
        (with(&["--depth", "0", "--command", "decoys", "--count", "1", "--window", "4"]), "decoys needs --count"),
        (with(&["--depth", "0", "--command", "decoys", "--count", "1", "--for-op7", "true"]), "decoys needs --count"),
        (with(&["--depth", "0", "--command", "decoys", "--count", "1", "--key-version", "0"]), "decoys needs --count"),
        (with(&["--depth", "0", "--command", "decoys", "--count", "1", "--decoy-filter", "recent", "--window", "4"]), "activity or holder"),
        (with(&["--depth", "0", "--command", "decoys", "--count", "1", "--exclude", "0x01"]), "--exclude: 32 bytes"),
        (with(&["--depth", "0", "--command", "decoys", "--count", "1", "--recipient", "0x01"]), "--recipient: 32 bytes"),
        (with(&["--depth", "0", "--for-op7", "false", "--recipient", &a32]), "go with --command decoys only"),
    ] {
        let e = cli(&args, None).unwrap_err();
        assert!(e.contains(want), "{args:?}: want {want}: {e}");
    }
}

/// `pqz-read --command decoys` against a local `anvil` (capped; stopped by the test): the registry's `0x0142` list and keys, the
/// token's account counters written by `anvil_setStorageAt` over 21 blocks. The sync point bounds the list (UAs listed after it
/// are never candidates, never chosen); `--ua` and `--exclude` never chosen; the default is every listed UA (no filter); the
/// activity filter's candidates and recency weights (`activity`, `holder`), and its pick; too few refused; each chosen decoy's
/// proven key; an unproven key, a sync point past the read block, a short window and an uncatalogued token refused.
#[test]
#[ignore]
fn decoys_against_anvil() {
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{port}");
    let bin = std::env::var("ANVIL").unwrap_or_else(|_| "anvil".into());
    let _anvil = Anvil(Command::new(bin).args(["--port", &port.to_string(), "--silent"]).stdout(Stdio::null()).spawn().unwrap());
    assert!((0..100).any(|_| {
        std::thread::sleep(std::time::Duration::from_millis(100));
        rpc(&url, "eth_chainId", json!([])).is_string()
    }), "anvil did not start");
    let chain_id = u64::from_str_radix(rpc(&url, "eth_chainId", json!([])).as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    let genesis = rpc(&url, "eth_getBlockByNumber", json!(["0x0", false]))["hash"].as_str().unwrap().to_string();
    let root = w32(&json!("0xda865ec17214f25b93cdb133d719c79392c290a4b9089fd0bba156256c521500"));
    let n = Node { url: url.clone(), root, chain_id, uid: w32(&json!(genesis)) };
    let (factory, token, reg, reg2) = (a20(FACTORY), a20("0x000000000000000000000000000000000000dec1"),
        a20("0x000000000000000000000000000000000000dec0"), a20("0x000000000000000000000000000000000000dec2"));
    n.catalogue(&factory, &token, 4, true);
    n.clone_of(&token, &reg);
    // reg2's token (owner 2026-11-08: `--registry` is the token's): the same kind, its env naming reg2
    let token2 = a20("0x000000000000000000000000000000000000dec3");
    n.catalogue(&factory, &token2, 4, true);
    n.clone_of(&token2, &reg2);
    let mine = |b: u64| rpc(&url, "anvil_mine", json!([format!("0x{b:x}")]));
    let head = || u64::from_str_radix(rpc(&url, "eth_blockNumber", json!([])).as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    let ua = |i: u8| [i; 32];
    let list = |r: &[u8; 20], from: u64, uas: std::ops::RangeInclusive<u8>, proven: u8| {
        for (j, i) in uas.clone().enumerate() {
            n.set(r, &k(&be(from + j as u64), &k(&be(0x0142), &be(reg_slot("uaAt")))), &ua(i));
            let ptr = a20(&format!("0x{:040x}", 0xc0de00 + u64::from(i)));
            let mut rec = word_of(&ptr);
            rec[11] = proven;
            n.set(r, &k(&be(0), &k(&ua(i), &be(reg_slot("pqzKey")))), &rec);
            n.code(&ptr, &json!(hx(&[vec![0u8], vec![i; st::PK_BYTES]].concat())));
        }
        n.set(r, &k(&be(0x0142), &be(reg_slot("uaCount"))), &be(from + uas.len() as u64));
    };
    // the account counters of `ua(i)`: `acct[ua][0]` word 0 `pendingCount ‖ rolled` (low end first), the UA's `sendCounter`
    let acct = |i: u8, pending: u64, rolled: u64, sent: u64| {
        let base = k(&be(0), &k(&ua(i), &add(&root, 8)));
        let mut w0 = be(pending);
        w0[16..24].copy_from_slice(&rolled.to_be_bytes());
        n.set(&token, &base, &w0);
        n.set(&token, &k(&ua(i), &add(&root, 12)), &be(sent));
    };
    // group 3g (KV-7): `ua(i)`'s version 1 with a key of `len` bytes, `current` its version; latest 1
    let version1 = |i: u8, len: usize, current: u64| {
        let ptr = a20(&format!("0x{:040x}", 0xc1de00 + u64::from(i)));
        let mut rec = word_of(&ptr);
        rec[11] = 1;
        n.set(&reg, &k(&be(1), &k(&ua(i), &be(reg_slot("pqzKey")))), &rec);
        n.code(&ptr, &json!(hx(&[vec![0u8], vec![0xF0 | i; len]].concat())));
        let mut vw = be(1);
        vw[16..24].copy_from_slice(&current.to_be_bytes());
        n.set(&reg, &k(&ua(i), &be(reg_slot("pqzVersions"))), &vw);
    };
    list(&reg, 0, 1..=12, 1);
    list(&reg2, 0, 9..=9, 0);
    (3..=8).for_each(|i| acct(i, 1, 0, 1));
    // `anvil_setStorageAt` writes the head block's state: a write at head `h` is seen from block `h` on
    mine(1);
    let sync = head(); // 1: twelve listed
    mine(1);
    list(&reg, 12, 13..=16, 1); // at block 2
    version1(14, st::PK_BYTES, 0); // pending: this set's key, not current
    version1(15, st::PK_BYTES - 32, 0); // another set's length: never current here, not pending
    version1(16, st::PK_BYTES, 1); // rotated: its decoy key is version 1's
    acct(7, 2, 0, 1); // u7 active at block 2, before the window
    mine(10); // 11 = block − window
    acct(3, 1, 0, 2); // u3: a debit at block 12, the older half
    mine(5); // 16 = block − window / 2
    acct(4, 2, 0, 1); // u4: a credit at block 17, the newer half
    acct(5, 1, 1, 1); // u5: a rollover
    acct(6, 1, 0, 2); // u6: a debit
    mine(4);
    assert_eq!((sync, head()), (1, 21));

    let cid = chain_id.to_string();
    let run = |r: &[u8; 20], tok: &str, x: &[&str]| {
        let mut a = s(&["--rpc", &url, "--chain-id", &cid, "--chain-uid", &genesis, "--factory", FACTORY, "--registry", &hx(r), "--token", tok,
            "--ua", &hx(&ua(1)), "--depth", "0", "--command", "decoys", "--exclude", &hx(&ua(2))]);
        a.extend(s(x));
        cli(&a, None)
    };
    let (tok, tok2) = (hx(&token), hx(&token2));
    let uas = |v: &Value| -> Vec<String> { serde_json::from_value(v.clone()).unwrap() };
    let range = |r: std::ops::RangeInclusive<u8>| r.map(|i| hx(&ua(i))).collect::<Vec<_>>();

    // the candidates (`--words`: pickDecoys's request): the list up to the sync point, less --ua and --exclude; no filter
    let w = run(&reg, &tok, &["--count", "3", "--sync-block", "1", "--words"]).unwrap();
    assert_eq!(w["request"], json!({"candidates": range(3..=12), "exclude": [hx(&ua(2)), hx(&ua(1))], "count": 3}), "sync 1");
    assert_eq!((&w["syncBlock"], &w["listCount"], &w["block"]), (&json!(1), &json!(12), &json!(21)));
    let w = run(&reg, &tok, &["--count", "3", "--words"]).unwrap();
    let listed = [range(3..=13), range(15..=16)].concat();
    assert_eq!(uas(&w["request"]["candidates"]), listed, "the read block's list (default sync point), never the pending ua(14)");
    let d = run(&reg, &tok, &["--count", "13"]).unwrap();
    let mut got: Vec<String> = d["decoys"].as_array().unwrap().iter().map(|l| l["ua"].as_str().unwrap().to_string()).collect();
    got.sort();
    assert_eq!(got, listed, "every candidate but the pending one");
    for l in d["decoys"].as_array().unwrap() {
        let i = h(&l["ua"])[0];
        let want = if i == 16 { vec![0xF0 | i; st::PK_BYTES] } else { vec![i; st::PK_BYTES] };
        assert_eq!(h(&l["pk"]), want, "ua({i}): the key of its current version");
    }
    assert!(run(&reg, &tok, &["--count", "14"]).unwrap_err().contains("pickDecoys: Argument"), "the pending UA never fills the count");
    // every candidate up to the sync point, exactly, when all are needed; one more is too few
    let d = run(&reg, &tok, &["--count", "10", "--sync-block", "1"]).unwrap();
    let mut got: Vec<String> = d["decoys"].as_array().unwrap().iter().map(|l| l["ua"].as_str().unwrap().to_string()).collect();
    got.sort();
    assert_eq!(got, range(3..=12), "never a UA listed after the sync point, never --ua or --exclude");
    for l in d["decoys"].as_array().unwrap() {
        let i = h(&l["ua"])[0];
        assert_eq!(h(&l["pk"]), vec![i; st::PK_BYTES], "the decoy's registered key");
    }
    assert!(run(&reg, &tok, &["--count", "11", "--sync-block", "1"]).unwrap_err().contains("pickDecoys: Argument"), "too few");
    // `--recipient`: excluded, named to the pick; `legs` the recipient once and the decoys, in the pick's shuffled order
    let w = run(&reg, &tok, &["--count", "2", "--sync-block", "1", "--recipient", &hx(&ua(5)), "--words"]).unwrap();
    let cands = [range(3..=4), range(6..=12)].concat();
    let want = json!({"candidates": cands, "exclude": [hx(&ua(2)), hx(&ua(1)), hx(&ua(5))], "count": 2, "recipient": hx(&ua(5))});
    assert_eq!(w["request"], want, "--recipient --words");
    let d = run(&reg, &tok, &["--count", "9", "--sync-block", "1", "--recipient", &hx(&ua(5))]).unwrap();
    let mut legs = uas(&d["legs"]);
    legs.sort();
    assert_eq!(legs, range(3..=12), "the recipient once with every decoy: {d}");
    assert!(run(&reg, &tok, &["--count", "1"]).unwrap().get("legs").is_none(), "no legs without --recipient");
    for _ in 0..8 {
        let d = uas(&json!(run(&reg, &tok, &["--count", "4"]).unwrap()["decoys"].as_array().unwrap().iter().map(|l| l["ua"].clone()).collect::<Vec<_>>()));
        assert_eq!(d.iter().collect::<std::collections::BTreeSet<_>>().len(), 4, "distinct");
        assert!(d.iter().all(|u| listed.contains(u)), "candidates only");
    }
    // the option: active in the token in the last 10 blocks, weighted by recency
    let f = |filter: &str| run(&reg, &tok, &["--count", "1", "--decoy-filter", filter, "--window", "10", "--words"]).unwrap()["request"].clone();
    let act = f("activity");
    assert_eq!((uas(&act["candidates"]), &act["weights"]), (range(3..=6), &json!([1, 2, 2, 2])), "activity");
    let hold = f("holder");
    assert_eq!((uas(&hold["candidates"]), &hold["weights"]), (vec![hx(&ua(3)), hx(&ua(6))], &json!([1, 2])), "holder: sendCounter only");
    let d = run(&reg, &tok, &["--count", "4", "--decoy-filter", "activity", "--window", "10"]).unwrap();
    let mut got: Vec<String> = d["decoys"].as_array().unwrap().iter().map(|l| l["ua"].as_str().unwrap().to_string()).collect();
    got.sort();
    assert_eq!(got, range(3..=6), "the filter's pick");
    assert!(run(&reg, &tok, &["--count", "5", "--decoy-filter", "activity", "--window", "10"]).unwrap_err().contains("Argument"), "too few active");
    // refusals
    assert!(run(&reg2, &tok2, &["--count", "0"]).is_ok(), "count 0 (positive control of the next)");
    assert!(run(&reg2, &tok2, &["--count", "1"]).unwrap_err().contains("is not a proven key"), "an unproven key");
    assert!(run(&reg2, &tok, &["--count", "0"]).unwrap_err().contains("R6: --registry is not the token's registry"), "reg2 is not tok's");
    assert!(run(&reg, &tok, &["--count", "1", "--sync-block", "22"]).unwrap_err().contains("past the read block"));
    assert!(run(&reg, &tok, &["--count", "1", "--decoy-filter", "activity", "--window", "1"]).unwrap_err().contains("--window"));
    assert!(run(&reg, &tok, &["--count", "1", "--decoy-filter", "activity", "--window", "22"]).unwrap_err().contains("--window"));
    assert!(run(&reg, UNLISTED, &["--count", "1"]).unwrap_err().contains("R5"), "the token catalogued");
    // R3: every block read re-checked after the last read (the read block, the sync block), through a proxy that changes the
    // sync block's hash on its re-check; the proxy alone changes nothing (positive control)
    let via = |proxy: String| {
        let a = s(&["--rpc", &proxy, "--chain-id", &cid, "--chain-uid", &genesis, "--factory", FACTORY, "--registry", &hx(&reg), "--token",
            &tok, "--ua", &hx(&ua(1)), "--depth", "0", "--command", "decoys", "--count", "1", "--sync-block", "1", "--words"]);
        cli(&a, None)
    };
    assert!(via(liar(url.clone(), "none")).is_ok());
    assert!(via(liar(url.clone(), "hash4")).unwrap_err().contains("R3: the block changed"), "the sync block re-checked");
    // R1 (owner 2026-11-08): the decoys over several nodes, failover and a strict majority
    let hits = || std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let same = node(url.clone(), hits(), |_, _, r, _| Some(r));
    let lists = |urls: &[&str], agree: bool| {
        let mut a: Vec<String> = urls.iter().flat_map(|u| s(&["--rpc", u])).collect();
        a.extend(s(&["--chain-id", &cid, "--chain-uid", &genesis, "--factory", FACTORY, "--registry", &hx(&reg), "--token", &tok, "--ua",
            &hx(&ua(1)), "--depth", "0", "--command", "decoys", "--exclude", &hx(&ua(2)), "--count", "3", "--sync-block", "1", "--words"]));
        if agree {
            a.push("--rpc-agree".into());
        }
        cli(&a, None)
    };
    let one = run(&reg, &tok, &["--count", "3", "--sync-block", "1", "--words"]).unwrap();
    assert_eq!(lists(&["http://127.0.0.1:1", &url], false).unwrap()["request"], one["request"], "failover past a dead node");
    assert_eq!(lists(&[&url, &same], true).unwrap()["request"], one["request"], "two agreeing nodes");
    let d = {
        let mut a: Vec<String> = [&url, &same].iter().flat_map(|u| s(&["--rpc", u])).collect();
        a.extend(s(&["--chain-id", &cid, "--chain-uid", &genesis, "--factory", FACTORY, "--registry", &hx(&reg), "--token", &tok, "--ua",
            &hx(&ua(1)), "--depth", "0", "--command", "decoys", "--exclude", &hx(&ua(2)), "--count", "4", "--rpc-agree"]));
        cli(&a, None).unwrap()
    };
    assert_eq!(d["decoys"].as_array().unwrap().len(), 4, "one pick, the keys a majority returned: {d}");
}
