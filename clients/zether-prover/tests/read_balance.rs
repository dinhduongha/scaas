//! zether-limits D5 end to end: a balance > 2^44 is out of reach of a device BSGS, is held and
//! spent through the wallet cache (`checkBalance`, no BSGS), and after the cache is lost the
//! native `zether-read-balance` recovers it from the pasted ciphertext. The CLI runs with the
//! smallest bound that covers the balance (2^45, table 2^22) to keep the test short. ARCH-POS-13 (ua-rs-sign T15c): the
//! wallet half needs the raw commands (feature `hazmat`); `--rpc` is refused before any request goes out.
#![cfg_attr(not(feature = "hazmat"), allow(dead_code, unused_imports))]

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{json, Value};
use zether_prover::api::{call, hx};
use zether_prover::curve::{decode_point, encode_point, generator, point_len, Bls12381, Fr, ZCurve, G};
#[cfg(feature = "bn254")]
use zether_prover::curve::Bn254;
use zether_prover::elgamal::Ciphertext;
use zether_prover::vectors::MNEMONIC;

const CLI: &str = env!("CARGO_BIN_EXE_zether-read-balance");

fn api(cmd: &str, v: Value) -> Result<Value, String> {
    call(cmd, &v.to_string()).map(|s| serde_json::from_str(&s).unwrap())
}

fn pt<C: ZCurve>(v: &Value) -> G<C> {
    decode_point::<C>(&hex::decode(&v.as_str().unwrap()[2..]).unwrap()).unwrap()
}

fn read_balance(args: &[&str], key: &Value) -> Result<Value, String> {
    let mut child = Command::new(CLI).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().unwrap();
    // A CLI that refuses its arguments exits before reading stdin: the pipe breaks, the exit status carries the verdict.
    if let Err(e) = child.stdin.take().unwrap().write_all(key.to_string().as_bytes()) {
        assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe, "{e}");
    }
    let out = child.wait_with_output().unwrap();
    if out.status.success() {
        Ok(serde_json::from_slice(&out.stdout).unwrap())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).into_owned())
    }
}

#[cfg(feature = "hazmat")]
#[test]
fn big_balance_cache_spend_and_cli_recovery_bls12_381() {
    recovery::<Bls12381>();
}

#[cfg(all(feature = "bn254", feature = "hazmat"))]
#[test]
fn big_balance_cache_spend_and_cli_recovery_bn254() {
    recovery::<Bn254>();
}

fn recovery<C: ZCurve>() {
    let curve = C::NAME;
    let n = point_len::<C>();
    let (k0, k1) = (json!({"mnemonic": MNEMONIC, "coin": 60, "account": 0}), json!({"mnemonic": MNEMONIC, "coin": 60, "account": 1}));
    let (a, b) = (api("keygen", json!({"curve": curve, "key": k0})).unwrap(), api("keygen", json!({"curve": curve, "key": k1})).unwrap());
    let bal: u64 = (1 << 44) + (1 << 34);
    let acc = api("encrypt", json!({"curve": curve, "Y": a["Y"], "amount": bal.to_string()})).unwrap();

    // Device BSGS (scaled down: table 2^18, bound 2^24) cannot read it: the wallet sends the user to the CLI.
    let e = api("decrypt", json!({"curve": curve, "key": k0, "ct": acc, "tableBits": 18, "boundBits": 24})).unwrap_err();
    assert!(e.contains("zether-read-balance"), "{e}");

    // Cache: a right balance validates, a wrong one does not.
    let check = |acc: &Value, b: u64| api("checkBalance", json!({"curve": curve, "key": k0, "acc": acc, "balance": b.to_string()})).unwrap()["ok"].clone();
    assert_eq!(check(&acc, bal), json!(true));
    assert_eq!(check(&acc, bal - 1), json!(false));

    // Spend from the cached balance: v > 2^32 plus an inner fee.
    let v: u64 = (1 << 33) + 7;
    let fee: u64 = 300;
    let t = api("proveTransfer", json!({
        "curve": curve, "key": k0, "chainId": 31337, "chainUid": hx(&[0x24; 32]),
        "token": "0x5fbdb2315678afecb367f032d93f642f64180aa3",
        "sendCounter": 0, "accSeq": 1, "validUntilBlock": 100, "acc": acc, "balance": bal.to_string(), "yTo": b["Y"],
        "amount": v.to_string(), "fee": fee, "beneficiary": hx(&[0x22; 32]),
    })).unwrap();
    assert_eq!(api("verifyTransfer", json!({"curve": curve, "statement": t["statement"], "proof": t["proof"]})).unwrap()["ok"], json!(true));
    // The token's debit: acc −= (C_deb + [fee]G, D_out). Payload = 96 B ‖ salt(16) ‖ Y_f ‖ Y_t ‖ C_out ‖ D_out ‖ C_deb ‖ C_aud.
    let pl = hex::decode(&t["payload"].as_str().unwrap()[2..]).unwrap();
    let at = |i: usize| decode_point::<C>(&pl[112 + n * i..112 + n * (i + 1)]).unwrap();
    let (d_out, c_deb) = (at(3), at(4));
    let g = generator::<C>();
    let acc2 = Ciphertext::<C> { c: pt::<C>(&acc["C"]) - c_deb - g * Fr::<C>::from(fee), d: pt::<C>(&acc["D"]) - d_out };
    let enc = |p: &G<C>| hx(&encode_point::<C>(p));
    let acc2_j = json!({"C": enc(&acc2.c), "D": enc(&acc2.d)});
    let left = bal - v - fee;
    assert!(left > 1 << 44);
    assert_eq!(check(&acc2_j, left), json!(true), "cache update b -= v + fee");

    // Cache lost: the CLI recovers the balance from the pasted ciphertext; the table file is
    // written on the first run, then loaded and verified on the second.
    let dir = std::env::temp_dir().join(format!("zrb-{}-{curve}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join(format!("{curve}-22.bsgs"));
    let ct = format!("{}:{}", acc2_j["C"].as_str().unwrap(), acc2_j["D"].as_str().unwrap());
    let args = ["--curve", curve, "--table-bits", "22", "--bound-bits", "45", "--ct", &ct, "--table-file", file.to_str().unwrap()];
    for _ in 0..2 {
        let out = read_balance(&args, &k0).unwrap();
        // review N3: a pasted ciphertext alone is the user's word, neither verified nor refuted.
        assert_eq!(out, json!({"balance": left.to_string(), "accSeq": null, "block": null, "source": "pasted"}));
    }
    assert_eq!(std::fs::metadata(&file).unwrap().len(), (8 + 1 + curve.len() + 1) as u64 + (12 << 22));
    // A bound below the balance, out-of-range knobs and a table file of another size are refused.
    assert!(read_balance(&["--curve", curve, "--table-bits", "20", "--bound-bits", "21", "--ct", &ct], &k0).is_err());
    assert!(read_balance(&["--curve", curve, "--table-bits", "28", "--ct", &ct], &k0).is_err());
    assert!(read_balance(&["--curve", curve, "--table-bits", "19", "--ct", &ct], &k0).is_err());
    assert!(read_balance(&["--curve", curve, "--bound-bits", "55", "--ct", &ct], &k0).is_err());
    let other = ["--curve", curve, "--table-bits", "23", "--bound-bits", "45", "--ct", &ct, "--table-file", file.to_str().unwrap()];
    assert!(read_balance(&other, &k0).unwrap_err().contains("not 2^23"));

    std::fs::remove_dir_all(&dir).unwrap();
}

/// ARCH-POS-13 (ua-rs-sign T14b, Fable P3-4): a pasted `--ct` exists only with feature `hazmat` (a ciphertext typed in by
/// hand is chosen by whoever handed it over); `--rpc` without the holder's configuration (R1–R5: chain id, chain_uid, factory,
/// token, depth or finalized) is refused before any request goes out. The URL's port is closed again before the call, so a
/// build that sent the request fails fast instead of waiting on a listener that never answers.
#[test]
fn ct_only_with_hazmat_and_rpc_only_as_a_reading_layer() {
    let k0 = json!({"mnemonic": MNEMONIC, "coin": 60, "account": 0});
    let y = zether_prover::keys::ZetherKey::<Bls12381>::conf(&zether_prover::keys::seed_from_mnemonic(MNEMONIC, "").unwrap()[..], 60, 0).unwrap();
    let ct = zether_prover::elgamal::encrypt(&y.y, 77, &Fr::<Bls12381>::from(5u64));
    let pasted = format!("{}:{}", hx(&encode_point::<Bls12381>(&ct.c)), hx(&encode_point::<Bls12381>(&ct.d)));
    let r = read_balance(&["--curve", "bls12381", "--table-bits", "20", "--bound-bits", "24", "--ct", &pasted], &k0);
    if cfg!(feature = "hazmat") {
        assert_eq!(r.unwrap()["balance"], json!("77"), "hazmat: the pasted path");
    } else {
        assert!(r.unwrap_err().contains("unknown argument --ct"), "release: no --ct");
    }
    let url = format!("http://{}", std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap());
    let tok = "0x5fbdb2315678afecb367f032d93f642f64180aa3";
    for missing in ["--chain-id", "--chain-uid", "--factory", "--token", "--depth"] {
        let mut a = vec!["--curve", "bls12381", "--table-bits", "20", "--rpc", &url, "--chain-id", "31337", "--chain-uid", tok,
            "--factory", tok, "--token", tok, "--depth", "1"];
        let i = a.iter().position(|x| *x == missing).unwrap();
        a.drain(i..i + 2);
        assert!(read_balance(&a, &k0).unwrap_err().contains("--rpc needs"), "{missing}");
    }
    let both = ["--curve", "bls12381", "--rpc", &url, "--chain-id", "1", "--chain-uid", tok, "--factory", tok, "--token", tok, "--depth",
        "1", "--finalized"];
    assert!(read_balance(&both, &k0).unwrap_err().contains("--rpc needs"), "one of --depth / --finalized");
}

fn b64url(b: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut s = String::new();
    for c in b.chunks(3) {
        let n = c.iter().enumerate().fold(0u32, |a, (i, x)| a | (u32::from(*x) << (16 - 8 * i)));
        for i in 0..=c.len() {
            s.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    s
}

/// clientkeys `sealBalanceCache` of `entries` under the conf key of `k` (AES-256-GCM, HKDF-SHA256 of `x`).
fn seal(k: &zether_prover::keys::ZetherKey<Bls12381>, entries: &Value, path: &std::path::Path) {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    let mut ck = [0u8; 32];
    hkdf::Hkdf::<sha2::Sha256>::new(None, &zether_prover::curve::encode_scalar::<Bls12381>(&k.x)).expand(b"scaas-zether-balance-cache-v1", &mut ck).unwrap();
    let iv = [7u8; 12];
    let ct = aes_gcm::Aes256Gcm::new_from_slice(&ck).unwrap()
        .encrypt(&aes_gcm::Nonce::from(iv), Payload { msg: entries.to_string().as_bytes(), aad: b"zether-cache:bls12381" })
        .unwrap();
    std::fs::write(path, json!({"iv": b64url(&iv), "ct": b64url(&ct)}).to_string()).unwrap();
}

/// `{k: v}`.
fn one(k: &str, v: Value) -> Value {
    Value::Object(serde_json::Map::from_iter([(k.to_string(), v)]))
}

fn kat_key(id: &str, account: u32) -> Value {
    let keys: Value = serde_json::from_str(&std::fs::read_to_string(format!("{}/../../smartcontracts/vectors/ua/keys.json", env!("CARGO_MANIFEST_DIR"))).unwrap()).unwrap();
    let m = keys["mnemonics"].as_array().unwrap().iter().find(|m| m["id"] == id).unwrap();
    json!({"mnemonic": m["words"], "passphrase": m["passphrase"], "coin": 60, "account": account})
}

/// The holder's own balance-cache box (Fable P3-4): clientkeys' box (`smartcontracts/vectors/ua/zether.json`) opens under its
/// key (the entries are read; this key's UA has none there), not under another key; a box with this key's entry gives the
/// cached balance without any ciphertext.
#[test]
fn the_holders_cache_box() {
    let z: Value = serde_json::from_str(&std::fs::read_to_string(format!("{}/../../smartcontracts/vectors/ua/zether.json", env!("CARGO_MANIFEST_DIR"))).unwrap()).unwrap();
    let r = &z["cacheBox"][0];
    let dir = std::env::temp_dir().join(format!("zrb-box-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("box.json");
    std::fs::write(&file, r["box"].to_string()).unwrap();
    let k = kat_key(r["mnemonic"].as_str().unwrap(), r["account"].as_u64().unwrap() as u32);
    let tok = "0x5fbdb2315678afecb367f032d93f642f64180aa3";
    let args = ["--curve", "bls12381", "--cache-box", file.to_str().unwrap(), "--token", tok];
    assert!(read_balance(&args, &k).unwrap_err().contains("no entry for this key's UA"), "clientkeys' box opens");
    assert!(read_balance(&args, &kat_key(r["mnemonic"].as_str().unwrap(), 1)).unwrap_err().contains("does not open"), "another key");
    let key = zether_prover::api::key::<Bls12381>(&json!({"key": k})).unwrap();
    let id = format!("{}:{tok}", hx(&key.ua()));
    seal(&key, &one(&id, json!({"ua": hx(&key.ua()), "token": tok, "accSeq": 3, "balance": "18014398509481983"})), &file);
    let out = read_balance(&args, &k).unwrap();
    assert_eq!(out, json!({"balance": "18014398509481983", "accSeq": 3, "block": null, "source": "cache"}));
    std::fs::remove_dir_all(&dir).unwrap();
}

fn rpc(url: &str, method: &str, params: Value) -> Value {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string();
    let out = Command::new("curl").args(["-s", "-X", "POST", "-H", "content-type: application/json", "--data", &body, url]).output().unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
    v["result"].clone()
}

/// Stops the local anvil when the test ends, whatever the outcome.
struct Anvil(std::process::Child);
impl Drop for Anvil {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn add(a: &[u8; 32], i: u64) -> [u8; 32] {
    let mut o = *a;
    let mut c = u128::from(i);
    for b in o.iter_mut().rev() {
        let t = u128::from(*b) + (c & 0xff);
        *b = t as u8;
        c = (c >> 8) + (t >> 8);
    }
    o
}

/// `zether-read-balance --rpc` as a reading layer (R1–R7, spec §4.2) against a local `anvil` (`ANVIL`, default `anvil` on the
/// PATH; run with `--ignored` under `scripts/capped`): the state is written into storage with `anvil_setStorageAt` (a
/// factory's `_info[token]`, the token's `psid` and two accounts), then read. R2: another chain id or chain_uid refused. R3:
/// a depth past the head refused; the words of the block at `head − depth`, not the head's. R5: a token the factory does not
/// catalogue, or catalogues as a PQZ kind, refused. R6: this key's account, not the other one. The cache box checked against
/// the state: a right entry is used without BSGS (`cache+rpc`), a stale one falls back to BSGS on the state.
#[test]
#[ignore]
fn rpc_reading_layer_against_anvil() {
    use zether_prover::curve::{keccak256, proof_system_id};
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
    let set = |addr: &str, slot: &[u8; 32], w: &[u8; 32]| {
        assert_eq!(rpc(&url, "anvil_setStorageAt", json!([addr, hx(slot), hx(w)])), json!(true));
    };
    let be = |n: u64| {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&n.to_be_bytes());
        w
    };
    let (factory, token, other_token, pqz_token) = ("0x00000000000000000000000000000000000fac70", "0x0000000000000000000000000000000000002e7a",
        "0x0000000000000000000000000000000000002e7b", "0x0000000000000000000000000000000000002e7c");
    let catalogue = |t: &str, kind: u8| {
        let mut k = [0u8; 32];
        k[12..].copy_from_slice(&hex::decode(&t[2..]).unwrap());
        let mut info = [0u8; 32];
        info[2] = 1; // exists
        info[11] = kind;
        set(factory, &keccak256(&[k, be(8)].concat()), &info);
    };
    catalogue(token, 2);
    catalogue(pqz_token, 4);
    let root = zether_prover::state::ROOT;
    set(token, &add(&root, 6), &proof_system_id::<Bls12381>());
    let seed = zether_prover::keys::seed_from_mnemonic(MNEMONIC, "").unwrap();
    let keys: Vec<_> = (0..2).map(|a| zether_prover::keys::ZetherKey::<Bls12381>::conf(&seed[..], 60, a).unwrap()).collect();
    // the account of key `i` holding `b` at accSeq 5
    let account = |i: usize, b: u64| {
        let k = &keys[i];
        let base = keccak256(&[k.ua(), add(&root, 8)].concat());
        let ct = zether_prover::elgamal::encrypt(&k.y, b, &Fr::<Bls12381>::from(11u64 + i as u64));
        for (f, p) in [ct.c, ct.d].iter().enumerate() {
            let s = add(&base, f as u64);
            set(token, &s, &be(2 * 128 + 1));
            let enc = encode_point::<Bls12381>(p);
            for (j, c) in enc.chunks(32).enumerate() {
                set(token, &add(&keccak256(&s), j as u64), &c.try_into().unwrap());
            }
        }
        set(token, &add(&base, 4), &be(5)); // accSeq 5 (the low 8 bytes)
    };
    account(0, 42);
    account(1, 99);
    rpc(&url, "anvil_mine", json!(["0x3"]));
    account(0, 43); // the head's state: a read at depth 1 must not see it
    rpc(&url, "anvil_mine", json!(["0x1"]));
    let k0 = json!({"mnemonic": MNEMONIC, "coin": 60, "account": 0});
    let cid = chain_id.to_string();
    let args = |chain: &str, uid: &str, tok: &str, depth: &str| {
        ["--curve", "bls12381", "--table-bits", "20", "--bound-bits", "24", "--rpc", &url, "--chain-id", chain, "--chain-uid", uid,
            "--factory", factory, "--token", tok, "--depth", depth].map(String::from).to_vec()
    };
    let run = |a: Vec<String>| read_balance(&a.iter().map(String::as_str).collect::<Vec<_>>(), &k0);
    let out = run(args(&cid, &genesis, token, "2")).unwrap();
    assert_eq!((out["balance"].clone(), out["accSeq"].clone(), out["source"].clone()), (json!("42"), json!(5), json!("rpc")), "R3, R6");
    assert_eq!(run(args(&cid, &genesis, token, "0")).unwrap()["balance"], json!("43"), "the head (positive control of R3)");
    assert!(run(args("1", &genesis, token, "2")).unwrap_err().contains("R2"), "another chain id");
    assert!(run(args(&cid, &hx(&[0x24; 32]), token, "2")).unwrap_err().contains("R2"), "another chain_uid");
    assert!(run(args(&cid, &genesis, token, "100")).unwrap_err().contains("R3"), "a depth past the head");
    assert!(run(args(&cid, &genesis, other_token, "2")).unwrap_err().contains("R5"), "not catalogued");
    assert!(run(args(&cid, &genesis, pqz_token, "2")).unwrap_err().contains("R5"), "catalogued as PQZ");
    // the cache box checked against the state
    let dir = std::env::temp_dir().join(format!("zrb-anvil-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("box.json");
    let id = format!("{}:{token}", hx(&keys[0].ua()));
    for (b, source, want) in [(42u64, "cache+rpc", "42"), (41, "rpc", "42")] {
        seal(&keys[0], &one(&id, json!({"ua": hx(&keys[0].ua()), "token": token, "accSeq": 5, "balance": b.to_string()})), &file);
        let mut a = args(&cid, &genesis, token, "2");
        a.extend(["--cache-box".to_string(), file.to_str().unwrap().to_string()]);
        let out = run(a).unwrap();
        assert_eq!((out["balance"].clone(), out["source"].clone()), (json!(want), json!(source)), "cache {b}");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// ua-rs-sign T15n (CTR-UA-29, owner 2026-11-07): the decoy steps' own arguments (no key, no stdin): `--decoy-count` with
/// `--exclude` and `--registry`, `--decoy-filter` with `--window`, `--decoy-keys` alone; the decoy flags only in those steps.
#[test]
fn decoy_arguments() {
    let u = format!("0x{}", "ab".repeat(32));
    let base = ["--curve", "bls12381", "--rpc", "http://127.0.0.1:1", "--chain-id", "1", "--chain-uid", &u, "--factory",
        "0x00000000000000000000000000000000000000aa", "--token", "0x00000000000000000000000000000000000000aa", "--depth", "0"];
    let with = |x: &[&str]| -> Vec<String> { base.iter().chain(x).map(|s| s.to_string()).collect() };
    for (args, want) in [
        (with(&["--registry", &u[..42]]), "go with --decoy-count or --decoy-keys"),
        (with(&["--exclude", &u]), "go with --decoy-count or --decoy-keys"),
        (with(&["--recipient", &u]), "go with --decoy-count or --decoy-keys"),
        (with(&["--decoy-keys", &u, "--registry", &u[..42], "--recipient", &u]), "--decoy-count with --exclude"),
        (with(&["--decoy-count", "1", "--registry", &u[..42], "--exclude", &u, "--recipient", "0x01"]), "--recipient: 32 bytes"),
        (with(&["--decoy-count", "2", "--exclude", &u]), "--rpc and --registry"),
        (with(&["--decoy-count", "2", "--registry", &u[..42]]), "--decoy-count with --exclude"),
        (with(&["--decoy-count", "2", "--registry", &u[..42], "--exclude", &u, "--window", "4"]), "--decoy-count with --exclude"),
        (with(&["--decoy-keys", &u, "--registry", &u[..42], "--exclude", &u]), "--decoy-count with --exclude"),
        (with(&["--decoy-keys", &u, "--decoy-count", "1", "--registry", &u[..42]]), "--decoy-count with --exclude"),
        (with(&["--decoy-keys", "0x01", "--registry", &u[..42]]), "32 bytes each"),
        (with(&["--decoy-count", "1", "--registry", &u[..42], "--exclude", &u, "--decoy-filter", "x", "--window", "4"]), "activity or holder"),
    ] {
        let e = read_balance(&args.iter().map(String::as_str).collect::<Vec<_>>(), &json!({})).unwrap_err();
        assert!(e.contains(want), "{args:?}: want {want}: {e}");
    }
}

/// T15n: a one-connection-at-a-time JSON-RPC proxy in front of `upstream` that answers the fourth non-genesis
/// `eth_getBlockByNumber` with another hash when `lie` (R3: the re-check of every block read); else a pass-through.
fn liar(upstream: String, lie: bool) -> String {
    use std::io::{BufRead, BufReader, Read};
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
                if lie && n == 4 {
                    res["hash"] = json!(hx(&[0x5a; 32]));
                }
            }
            let out = json!({"jsonrpc": "2.0", "id": 1, "result": res}).to_string();
            let _ = write!(c, "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{out}", out.len());
        }
    });
    url
}

/// ua-rs-sign T15n: the decoy steps against a local `anvil` (capped; stopped by the test). The registry's `0x0141` list,
/// records and SSTORE2 codes of real Zether keys, and the token's counters words, written by `anvil_setStorageAt` over 21
/// blocks. `--decoy-count`: `pickDecoys`'s request, the list up to the sync point (UAs listed later never candidates), less
/// the excluded; every listed UA by default (no filter); the activity filter's candidates and recency weights (`activity`,
/// `holder`). `--decoy-keys`: each chosen UA's `Y` (`UA(Y)` equal to it); a UA listed after the sync point, an unlisted UA and
/// a record whose `Y` is another UA's refused; R5 still checked.
#[test]
#[ignore]
fn decoys_against_anvil() {
    use zether_prover::curve::keccak256;
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
    let set = |addr: &str, slot: &[u8; 32], w: &[u8; 32]| {
        assert_eq!(rpc(&url, "anvil_setStorageAt", json!([addr, hx(slot), hx(w)])), json!(true));
    };
    let be = |n: u64| {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&n.to_be_bytes());
        w
    };
    let k2 = |a: &[u8; 32], b: &[u8; 32]| keccak256(&[*a, *b].concat());
    let (factory, token, pqz_token, reg, reg2) = ("0x00000000000000000000000000000000000fac70", "0x0000000000000000000000000000000000002e7a",
        "0x0000000000000000000000000000000000002e7c", "0x000000000000000000000000000000000000dec0", "0x000000000000000000000000000000000000dec2");
    let reg3 = "0x000000000000000000000000000000000000dec3";
    for (t, kind) in [(token, 2u8), (pqz_token, 4)] {
        let mut k = [0u8; 32];
        k[12..].copy_from_slice(&hex::decode(&t[2..]).unwrap());
        let mut info = [0u8; 32];
        info[2] = 1;
        info[11] = kind;
        set(factory, &k2(&k, &be(8)), &info);
    }
    let seed = zether_prover::keys::seed_from_mnemonic(MNEMONIC, "").unwrap();
    let keys: Vec<_> = (0..10).map(|a| zether_prover::keys::ZetherKey::<Bls12381>::conf(&seed[..], 60, a).unwrap()).collect();
    let ua = |i: usize| keys[i].ua();
    let y = |i: usize| encode_point::<Bls12381>(&keys[i].y);
    // `uaAt(0x0141, index) = ua` and its record `kind ‖ registeredAt ‖ keyPtr ‖ index` with the code `0x00 ‖ Y` of key `key`
    let register = |r: &str, index: u64, ua: [u8; 32], key: usize| {
        let ptr = format!("0x{:040x}", 0xc0de00 + index + if r == reg2 { 0x100 } else if r == reg3 { 0x200 } else { 0 });
        let mut rec = [0u8; 32];
        rec[..5].copy_from_slice(&index.to_be_bytes()[3..]);
        rec[5..25].copy_from_slice(&hex::decode(&ptr[2..]).unwrap());
        rec[30..].copy_from_slice(&[0x01, 0x41]);
        set(r, &k2(&ua, &be(0)), &rec);
        set(r, &k2(&be(index), &k2(&be(0x0141), &be(5))), &ua);
        rpc(&url, "anvil_setCode", json!([ptr, hx(&[vec![0u8], y(key)].concat())]));
        set(r, &k2(&be(0x0141), &be(4)), &be(index + 1));
    };
    // the counters word `accSeq ‖ pendingSeq ‖ lastRolledPendingSeq ‖ sendCounter` (low end first) of `ua(i)`
    let root = zether_prover::state::ROOT;
    let counters = |i: usize, pending: u64, sent: u64| {
        let mut w = be(1);
        w[16..24].copy_from_slice(&pending.to_be_bytes());
        w[..8].copy_from_slice(&sent.to_be_bytes());
        set(token, &add(&k2(&ua(i), &add(&root, 8)), 4), &w);
    };
    let mine = |b: u64| rpc(&url, "anvil_mine", json!([format!("0x{b:x}")]));
    (0..8).for_each(|i| register(reg, i as u64, ua(i), i));
    register(reg2, 0, [0xbb; 32], 2); // a record whose Y is another UA's
    register(reg3, 0, ua(2), 2);
    let mut other_kind = [0u8; 32]; // the same record, of kind 0x0142
    other_kind[5..25].copy_from_slice(&hex::decode(format!("{:040x}", 0xc0de00 + 0x200)).unwrap());
    other_kind[30..].copy_from_slice(&[0x01, 0x42]);
    set(reg3, &k2(&ua(2), &be(0)), &other_kind);
    (2..=5).for_each(|i| counters(i, 1, 1));
    // `anvil_setStorageAt` writes the head block's state: a write at head `h` is seen from block `h` on
    mine(1); // 1: the sync point, eight listed
    mine(1);
    (8..10).for_each(|i| register(reg, i as u64, ua(i), i)); // at block 2
    counters(5, 2, 1); // ua5 active at block 2, before the window
    mine(10);
    counters(2, 1, 2); // ua2: a debit at block 12, the older half
    mine(5);
    counters(3, 2, 1); // ua3: a credit at block 17, the newer half
    counters(4, 1, 2); // ua4: a debit
    mine(4);
    assert_eq!(rpc(&url, "eth_blockNumber", json!([])), json!("0x15"));

    let cid = chain_id.to_string();
    let run = |r: &str, tok: &str, x: &[&str]| {
        let mut a = ["--curve", "bls12381", "--rpc", &url, "--chain-id", &cid, "--chain-uid", &genesis, "--factory", factory, "--token", tok,
            "--depth", "0", "--registry", r].map(String::from).to_vec();
        a.extend(x.iter().map(|s| s.to_string()));
        read_balance(&a.iter().map(String::as_str).collect::<Vec<_>>(), &json!({}))
    };
    let hs = |r: std::ops::Range<usize>| r.map(|i| hx(&ua(i))).collect::<Vec<_>>();
    let ex = format!("{},{}", hx(&ua(0)), hx(&ua(1)));
    let out = run(reg, token, &["--decoy-count", "3", "--exclude", &ex, "--sync-block", "1"]).unwrap();
    assert_eq!(out["request"], json!({"candidates": hs(2..8), "exclude": hs(0..2), "count": 3}), "the list up to the sync point");
    assert_eq!((&out["syncBlock"], &out["listCount"], &out["block"]), (&json!(1), &json!(8), &json!(21)));
    assert_eq!(run(reg, token, &["--decoy-count", "3", "--exclude", &ex]).unwrap()["request"]["candidates"], json!(hs(2..10)), "default: the read block");
    // `--recipient`: excluded, and named to the pick (which then answers the shuffled `legs`)
    let out = run(reg, token, &["--decoy-count", "3", "--exclude", &ex, "--recipient", &hx(&ua(4)), "--sync-block", "1"]).unwrap();
    let (cands, excl) = ([hs(2..4), hs(5..8)].concat(), [hs(0..2), hs(4..5)].concat());
    let want = json!({"candidates": cands, "exclude": excl, "count": 3, "recipient": hx(&ua(4))});
    assert_eq!(out["request"], want, "--recipient");
    let f = |filter: &str| run(reg, token, &["--decoy-count", "1", "--exclude", &ex, "--decoy-filter", filter, "--window", "10"]).unwrap()["request"].clone();
    let act = f("activity");
    assert_eq!((&act["candidates"], &act["weights"]), (&json!(hs(2..5)), &json!([1, 2, 2])), "activity, by recency");
    let hold = f("holder");
    assert_eq!((&hold["candidates"], &hold["weights"]), (&json!([hx(&ua(2)), hx(&ua(4))]), &json!([1, 2])), "holder: sendCounter only");
    // the chosen decoys' keys
    let d = run(reg, token, &["--decoy-keys", &format!("{},{}", hx(&ua(7)), hx(&ua(2))), "--sync-block", "1"]).unwrap();
    assert_eq!(d["decoys"], json!([{"ua": hx(&ua(7)), "yTo": hx(&y(7))}, {"ua": hx(&ua(2)), "yTo": hx(&y(2))}]));
    assert!(run(reg, token, &["--decoy-keys", &hx(&ua(8))]).is_ok(), "listed by the read block (positive control of the next)");
    let no = |r: &str, u: &str, x: &[&str], want: &str| {
        let e = run(r, token, &[&["--decoy-keys", u][..], x].concat()).unwrap_err();
        assert!(e.contains(want), "want {want}: {e}");
    };
    no(reg, &hx(&ua(8)), &["--sync-block", "1"], "on the 0x0141 list up to the sync point");
    no(reg, &hx(&[0xcc; 32]), &[], "is not a registered Zether UA");
    no(reg2, &hx(&[0xbb; 32]), &[], "is not a registered Zether UA");
    no(reg3, &hx(&ua(2)), &[], "is not a registered Zether UA"); // kind 0x0142
    no(reg, &hx(&ua(2)), &["--sync-block", "22"], "past the read block");
    assert!(run(reg, pqz_token, &["--decoy-keys", &hx(&ua(2))]).unwrap_err().contains("R5"), "R5");
    assert!(run(reg, token, &["--decoy-count", "1", "--exclude", &ex, "--decoy-filter", "holder", "--window", "1"]).unwrap_err().contains("--window"));
    // R3: every block read re-checked after the last read (here the sync block, on its re-check); the proxy alone changes nothing
    let via = |proxy: String| {
        let a = ["--curve", "bls12381", "--rpc", &proxy, "--chain-id", &cid, "--chain-uid", &genesis, "--factory", factory, "--token", token,
            "--depth", "0", "--registry", reg, "--decoy-keys", &hx(&ua(2)), "--sync-block", "1"];
        read_balance(&a, &json!({}))
    };
    assert!(via(liar(url.clone(), false)).is_ok());
    assert!(via(liar(url.clone(), true)).unwrap_err().contains("R3: the block changed"), "the sync block re-checked");
}
