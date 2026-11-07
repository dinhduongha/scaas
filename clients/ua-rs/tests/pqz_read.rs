// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! ua-rs-sign T15m (ARCH-POS-13; spec no-decryption-oracle §4.2 R1–R7, §4.12): `pqz-read`, the PQZ reference reading layer.
//! Without a node: the holder's configuration is required before any request goes out. Against a local `anvil` (`ANVIL`,
//! default `anvil` on the PATH; `--ignored`, under `scripts/capped`; the anvil is killed when the test ends): PQZ state
//! written into storage and code with `anvil_setStorageAt` / `anvil_setCode` from three sources: the forge rows
//! (`state.json`, `PqzStateVectors.t.sol`: the words the tool reads equal the contract's byte for byte), the wallet rows
//! (`wallet_state.json`: real `pq_kat` keys decrypt their balances, the positive control) and `tests/pqz_chain` (an audited
//! op 1 to a real auditor key, a pending window past `INLINE_MAX`, a PQZH twin). Each refusal of R2, R3, R5 and R6 named.
//! The default set only (the rows' set). UNAUDITED.
#![cfg_attr(feature = "vectors", allow(dead_code, unused_imports))]
mod pqz_chain;

use pqz_chain::{h, hx, merge, Chain};
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
        &a32, "--depth", "1", "--for-op7", "false"]);
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
    let mut audit = without_op7.clone();
    audit.extend(s(&["--command", "auditRead", "--from-ua", &a32, "--send-counter", "0"]));
    assert!(cli(&audit, None).unwrap_err().contains("auditRead needs"), "auditRead: the entry's three fields");
    let mut other = without_op7.clone();
    other.extend(s(&["--command", "dec"]));
    assert!(cli(&other, None).unwrap_err().contains("balance or auditRead"), "no other command");
    for (f, v) in [("--rpc", "http://127.0.0.1:1"), ("--token", a20)] {
        let mut twice = full.clone();
        twice.extend(s(&[f, v]));
        assert!(cli(&twice, None).unwrap_err().contains("given twice"), "{f}: R1, one source; one value each");
    }
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
    /// `OpenFactory._info[token]`: `exists` and `kind`.
    fn catalogue(&self, factory: &[u8; 20], token: &[u8; 20], kind: u8, exists: bool) {
        let mut info = [0u8; 32];
        info[2] = exists as u8;
        info[11] = kind;
        self.set(factory, &k(&word_of(token), &be(8)), &info);
    }
    /// A words request's account (`balance`'s shape: the forge rows, the wallet rows, `Chain::bal`) into `token`'s storage,
    /// its key record into `registry`'s, its codes.
    fn account(&self, token: &[u8; 20], registry: &[u8; 20], psid: &Value, r: &Value) {
        let ua = w32(&r["ua"]);
        self.set(token, &add(&self.root, 2), &w32(psid));
        let base = k(&ua, &add(&self.root, 8));
        for (i, w) in r["account"].as_array().unwrap().iter().enumerate() {
            self.set(token, &add(&base, i as u64), &w32(w));
        }
        for e in r["pending"].as_array().unwrap() {
            self.set(token, &k(&be(e["index"].as_u64().unwrap()), &add(&base, 4)), &w32(&e["word"]));
        }
        for (i, w) in r["accWords"].as_array().unwrap().iter().enumerate() {
            self.set(token, &add(&base, 5 + i as u64), &w32(w));
        }
        self.set(registry, &k(&ua, &be(2)), &w32(&r["keyRecord"]));
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
        self.set(registry, &k(&w32(&aud["auditorUA"]), &be(2)), &w32(&aud["keyRecord"]));
        self.code(&a20(aud["key"]["address"].as_str().unwrap()), &aud["key"]["code"]);
    }
}

/// A one-connection-at-a-time JSON-RPC proxy in front of `upstream` that lies about the read block (R3): `number` answers the
/// first non-genesis `eth_getBlockByNumber` with the next block's number, `hash` the second one with another hash.
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
                if mode == "hash" && n == 2 {
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
    for a in forge["accounts"].as_array().unwrap() {
        n.account(&ft, &fr, &forge["psid"], a);
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
    for ua in [ua_a, ua_b] {
        let full = c.own(&ua, 1 << 20); // every pending slot, so the tool's window is its own
        n.account(&cw, &creg, &json!(hx(&st::PQZL_ID)), &full);
        n.account(&cwh, &creg, &json!(hx(&st::PQZH_ID)), &full);
    }
    let ent = &c.entries[&er];
    let aud_ptr = c.keys[&ua_aud];
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
    let bal = |mut a: Vec<String>, op7: bool| {
        a.extend(s(&["--for-op7", if op7 { "true" } else { "false" }]));
        a
    };
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
        assert_eq!((&r["psid"], &r["ua"], &r["forOp7"]), (&forge["psid"], &a["ua"], &json!(false)), "{}", a["name"]);
    }
    assert!(forge["accounts"].as_array().unwrap().iter().any(|a| !a["accWords"].as_array().unwrap().is_empty()), "a materialised acc");
    // auditRead's words of the forge entry
    let mut ar = on(ft_s, fr_s, forge["auditorUA"].as_str().unwrap());
    ar.extend(s(&["--command", "auditRead", "--from-ua", fe["fromUA"].as_str().unwrap(), "--send-counter", &fe["sendCounter"].to_string(),
        "--leg", "0"]));
    let r = words(ar.clone())["request"].clone();
    assert_eq!((&r["entryPtr"], &r["auditorMode"], &r["auditorUA"], &r["keyRecord"]),
        (&fe["entryPtr"], &forge["auditorMode"], &forge["auditorUA"], &forge["auditorKeyRecord"]));
    assert_eq!(r["blobs"], json!([fe["blob"], forge["auditorKey"]]));
    let ftw = word_of(&ft);
    assert_eq!(r["entryRef"], json!(hx(&n.entry_ref(&ft, &w32(&fe["fromUA"]), fe["sendCounter"].as_u64().unwrap()))));
    assert_eq!((&r["chainId"], &r["chainUid"], &r["token"]), (&json!(chain_id), &json!(genesis), &json!(hx(&ftw[12..]))));

    // the positive control: the wallet rows' balances with their own keys
    let wt_s = rows[0]["request"]["token"].as_str().unwrap();
    for (r, i) in rows.iter().zip(0u32..) {
        let out = cli(&bal(on(wt_s, WALLET_REG, r["request"]["ua"].as_str().unwrap()), false), Some(&kat(i))).unwrap();
        assert_eq!(out["value"], r["value"], "{}", r["name"]);
        assert!(out["block"].is_u64() && out["blockHash"].is_string());
    }
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
        a.extend(s(&["--command", "auditRead", "--from-ua", from, "--send-counter", ctr, "--leg", "0"]));
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
        json!(750), "the proxy alone changes nothing (positive control)");
    for t in [UNLISTED, NOT_EXISTS, ZETHER_TOKEN] {
        no(bal(on(t, WALLET_REG, ua_wa), false), Some(0), "R5: the token is not a PQZ token");
    }
    no(wa(), Some(1), "R6: the registry's PQZ key of --ua is not this key");
    no(audit(on(CW_TOKEN, CW_REG, &sb), &sa, "0"), Some(1), "R6: --ua is not the token's auditor");
    no(audit(head(on(CW_TOKEN, CW_REG, &saud)), &sa, "0"), Some(2), "R6: --ua is not the token's auditor");
    no(audit(on(CW_TOKEN, CW_REG, &saud), &sa, "1"), Some(2), "no entry of --from-ua");
    no(audit(on(CW_TOKEN, CW_REG, &saud), &sa, "0"), Some(1), "R6: the registry's PQZ key");
    // ua-rs's own refusal after the reading layer's checks: the auditor reads a leg the entry does not have
    let mut leg1 = audit(on(CW_TOKEN, CW_REG, &saud), &sa, "0");
    *leg1.last_mut().unwrap() = "1".into();
    no(leg1, Some(2), "ua-rs refused the words: Argument");
}
