//! zether-read-balance — read a Zether balance too large for the wallet's device BSGS (lost cache
//! on a big account, zether-limits §4–§5). Native only. UNAUDITED.
//!
//!   zether-read-balance --curve bls12381 [--table-bits 24] [--bound-bits 54] [--table-file PATH] [--pending]
//!                       [--rpc <url> --chain-id <n> --chain-uid <genesis hash> --factory <address> --token <address>
//!                        (--depth <n> | --finalized)]
//!                       [--cache-box <file> --token <address>]
//!                       (feature `hazmat` only: --ct <C hex>:<D hex>)
//!
//! The key is read from **stdin** as JSON, the `key` object of the prover API:
//! `{"x": "0x…"}` or `{"mnemonic": "…", "passphrase"?: "…", "coin": n, "account": n}` — piped from a
//! file (`< key.json`); a terminal on stdin is refused so the key is never echoed or left in the
//! scrollback. It never leaves this process.
//!
//! ARCH-POS-13 ("never a decryption oracle", owner 2026-11-06; ua-rs-sign T14b, spec no-decryption-oracle §4.2, §4.7, Fable
//! P3-4): this tool decrypts only a ciphertext it rebuilt from raw storage words it read itself, as a reading layer meeting
//! R1 to R7, or reads the holder's own balance-cache box:
//! - **`--rpc`** (R1) is the one source of every word, a node the holder names here (their own, or one they configured):
//!   never a default or a discovered endpoint. R2: `eth_chainId` and `eth_getBlockByNumber("0x0").hash` must equal
//!   `--chain-id` and `--chain-uid` (the genesis hash, NET-ALL-22). R3: one block, the chain's `finalized` block
//!   (`--finalized`) or `head − depth` (`--depth`, the holder's confirmation depth on a chain without finality,
//!   NET-EVM-04); every read names that block by hash (EIP-1898). R4: storage words only (`eth_getStorageAt`), no view.
//!   R5: the token is catalogued by `--factory` (`OpenFactory._info[token]`, slot 8: `exists` set, `kind` a Zether kind).
//!   R6: the account read is `acct[UA(Y)]` of this key, computed here. R7: every read happens before the key is used,
//!   and nothing after it goes back to the node. The URL and body go to `curl` on its stdin (`--config -`, `-q` first),
//!   never in argv. The words are parsed and rebuilt by `zether_prover::state` (the layout pinned by T19c).
//! - **`--cache-box`**: the box `{iv, ct}` of clientkeys `sealBalanceCache` (AES-256-GCM under `HKDF-SHA256(x,
//!   "scaas-zether-balance-cache-v1")`, AAD `zether-cache:bls12381`), the holder's own; its entry `<UA>:<token>`. With
//!   `--rpc` as well, the cached balance is checked against the state (`accSeq` and `[b]G == C − [x]D`) and used when it
//!   holds (no BSGS), else the state is read by BSGS.
//! - A pasted `--ct` (a ciphertext typed in by hand, chosen by whoever handed it over) exists only in a build with the
//!   test feature `hazmat`.
//!
//! `--table-bits` 20–27 (≈ 16 B × 2^bits of RAM; refused when free RAM is short), `--bound-bits` ≤ 54; worst case
//! 2^(bound − table) giant steps. `--table-file` loads and verifies a saved baby table (public data), or writes one after
//! generating it. Prints `{"balance": "<decimal>", "accSeq": n|null, "block": n|null, "source": "rpc"|"cache"|"cache+rpc"|"pasted"}`;
//! `accSeq` is what the wallet cache stores.

use std::io::{IsTerminal, Read};
use std::process::{Command, ExitCode, Stdio};

use serde_json::{json, Value};
use zeroize::Zeroizing;
#[cfg(feature = "bn254")]
use zether_prover::curve::Bn254;
use zether_prover::curve::{keccak256, Bls12381, ZCurve};
use zether_prover::elgamal::{check_ram, mem_available, BsgsParams, BsgsTable};
use zether_prover::keys::ZetherKey;
use zether_prover::state;

const TABLE_BITS_CLI: std::ops::RangeInclusive<u32> = 20..=27;
/// `OpenFactory._info` (slot 8): `creator(160) ‖ kind(8) ‖ version(64) ‖ exists(8)`; the Zether kinds (`IOpenFactory.TokenKind`
/// NORMAL_ZETHER, WRAPPED_ZETHER, NORMAL_ZETHER_REGULATED, WRAPPED_ZETHER_REGULATED).
const INFO_SLOT: u64 = 8;
const ZETHER_KINDS: [u8; 4] = [2, 3, 10, 11];

#[derive(Default)]
struct Args {
    curve: String,
    table_bits: u32,
    bound_bits: u32,
    table_file: Option<String>,
    pending: bool,
    #[cfg(feature = "hazmat")]
    ct: Option<String>,
    rpc: Option<String>,
    chain_id: Option<u64>,
    chain_uid: Option<String>,
    factory: Option<String>,
    token: Option<String>,
    depth: Option<u64>,
    finalized: bool,
    cache_box: Option<String>,
}

fn parse() -> Result<Args, String> {
    let mut a = Args { table_bits: 24, bound_bits: 54, ..Args::default() };
    let mut it = std::env::args().skip(1);
    while let Some(f) = it.next() {
        let mut val = || it.next().ok_or(format!("{f} needs a value"));
        match f.as_str() {
            "--curve" => a.curve = val()?,
            "--table-bits" => a.table_bits = val()?.parse().map_err(|_| "--table-bits: integer")?,
            "--bound-bits" => a.bound_bits = val()?.parse().map_err(|_| "--bound-bits: integer")?,
            "--table-file" => a.table_file = Some(val()?),
            "--pending" => a.pending = true,
            #[cfg(feature = "hazmat")]
            "--ct" => a.ct = Some(val()?),
            "--rpc" => a.rpc = Some(val()?),
            "--chain-id" => a.chain_id = Some(val()?.parse().map_err(|_| "--chain-id: integer")?),
            "--chain-uid" => a.chain_uid = Some(val()?),
            "--factory" => a.factory = Some(val()?),
            "--token" => a.token = Some(val()?),
            "--depth" => a.depth = Some(val()?.parse().map_err(|_| "--depth: integer")?),
            "--finalized" => a.finalized = true,
            "--cache-box" => a.cache_box = Some(val()?),
            _ => return Err(format!("unknown argument {f}")),
        }
    }
    if !TABLE_BITS_CLI.contains(&a.table_bits) {
        return Err("--table-bits must be 20..=27".into());
    }
    BsgsParams::new(a.table_bits, a.bound_bits).map_err(|e| e.to_string())?;
    #[cfg(feature = "hazmat")]
    let pasted = a.ct.is_some();
    #[cfg(not(feature = "hazmat"))]
    let pasted = false;
    if pasted && (a.rpc.is_some() || a.cache_box.is_some()) {
        return Err("--ct goes alone".into());
    }
    if !pasted && a.rpc.is_none() && a.cache_box.is_none() {
        return Err("give --rpc (with --chain-id, --chain-uid, --factory, --token, --depth or --finalized) and/or --cache-box".into());
    }
    if a.rpc.is_some()
        && (a.chain_id.is_none() || a.chain_uid.is_none() || a.factory.is_none() || a.token.is_none() || a.finalized == a.depth.is_some())
    {
        return Err("--rpc needs --chain-id, --chain-uid, --factory, --token and one of --depth / --finalized (R1–R5)".into());
    }
    if a.cache_box.is_some() && a.token.is_none() {
        return Err("--cache-box needs --token".into());
    }
    if (a.rpc.is_some() || a.cache_box.is_some()) && a.curve != "bls12381" {
        return Err("--rpc and --cache-box are bls12381 only".into());
    }
    Ok(a)
}

fn unhex(s: &str) -> Result<Vec<u8>, String> {
    hex::decode(s.trim().trim_start_matches("0x")).map_err(|_| format!("not hex: {s}"))
}

fn hx(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

/// A curl config file (read from curl's stdin): URL and body stay out of argv.
fn curl_config(url: &str, body: &str) -> String {
    let q = |s: &str| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"").replace(['\n', '\r'], ""));
    format!(
        "silent\nshow-error\nrequest = \"POST\"\nheader = \"content-type: application/json\"\nurl = {}\ndata-binary = {}\n",
        q(url),
        q(body)
    )
}

/// One JSON-RPC call to the one source (R1), through `curl` (http and https without a TLS dependency here).
fn rpc(url: &str, method: &str, params: Value) -> Result<Value, String> {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    let mut child = Command::new("curl")
        .args(["-q", "--config", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| format!("curl: {e}"))?;
    let cfg = curl_config(url, &body.to_string());
    let mut stdin = child.stdin.take().ok_or("curl: no stdin")?;
    std::io::Write::write_all(&mut stdin, cfg.as_bytes()).map_err(|e| e.to_string())?;
    drop(stdin);
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    let v: Value = serde_json::from_slice(&out.stdout).map_err(|_| format!("{method}: the node returned no JSON"))?;
    v.get("result").filter(|r| !r.is_null()).cloned().ok_or(format!("{method}: {}", v["error"]))
}

fn qty(v: &Value) -> Result<u64, String> {
    u64::from_str_radix(v.as_str().ok_or("a quantity expected")?.trim_start_matches("0x"), 16).map_err(|_| "a quantity expected".into())
}

/// `a + i` (mod 2^256), big-endian.
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

fn be(n: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&n.to_be_bytes());
    w
}

/// The words of one block (R3), by hash (EIP-1898), storage only (R4), from the one source (R1).
struct Reader<'a> {
    url: &'a str,
    block: u64,
    hash: String,
}

impl Reader<'_> {
    fn word(&self, address: &str, slot: &[u8; 32]) -> Result<[u8; 32], String> {
        let w = rpc(self.url, "eth_getStorageAt", json!([address, hx(slot), {"blockHash": self.hash}]))?;
        let b = unhex(w.as_str().ok_or("eth_getStorageAt: not a word")?)?;
        let mut o = [0u8; 32];
        o.get_mut(32usize.checked_sub(b.len()).ok_or("eth_getStorageAt: longer than a word")?..)
            .ok_or("word")?
            .copy_from_slice(&b);
        Ok(o)
    }
}

/// R1–R6: the words of `acct[ua]` of `token`, read at one final block of the configured chain from the one node, with the
/// location fields of `zether_prover::state`.
fn read_words(a: &Args, ua: &[u8; 32]) -> Result<Value, String> {
    let (url, token, factory) =
        (a.rpc.as_deref().ok_or("--rpc")?, a.token.as_deref().ok_or("--token")?, a.factory.as_deref().ok_or("--factory")?);
    let chain_uid = unhex(a.chain_uid.as_deref().ok_or("--chain-uid")?)?;
    // R2
    if Some(qty(&rpc(url, "eth_chainId", json!([]))?)?) != a.chain_id {
        return Err("R2: eth_chainId is not the configured chain".into());
    }
    let genesis = rpc(url, "eth_getBlockByNumber", json!(["0x0", false]))?;
    if unhex(genesis["hash"].as_str().ok_or("R2: no genesis hash")?)? != chain_uid {
        return Err("R2: the genesis hash is not the configured chain_uid".into());
    }
    // R3
    let tag = match a.depth {
        Some(d) => {
            let head = qty(&rpc(url, "eth_blockNumber", json!([]))?)?;
            format!("0x{:x}", head.checked_sub(d).ok_or("R3: the chain is shorter than the confirmation depth")?)
        }
        None => "finalized".into(),
    };
    let b = rpc(url, "eth_getBlockByNumber", json!([tag, false]))?;
    let r = Reader { url, block: qty(&b["number"])?, hash: b["hash"].as_str().ok_or("R3: no block hash")?.to_string() };
    // R5
    let t: [u8; 20] = unhex(token)?.try_into().map_err(|_| "--token: 20 bytes")?;
    let mut key = [0u8; 32];
    key[12..].copy_from_slice(&t);
    let info = r.word(factory, &keccak256(&[key, be(INFO_SLOT)].concat()))?;
    // counted from the low end: `kind` byte 20, `exists` byte 29
    if info[2] != 1 || !ZETHER_KINDS.contains(&info[11]) {
        return Err("R5: the token is not a Zether token catalogued by this factory".into());
    }
    // R4, R6: the account of this key
    let psid = r.word(token, &add(&state::ROOT, 6))?;
    let base = keccak256(&[*ua, add(&state::ROOT, 8)].concat());
    let mut account = Vec::new();
    let mut data = Vec::new();
    for i in 0..6 {
        let w = r.word(token, &add(&base, i))?;
        if i < 4 && w != [0; 32] {
            let d = keccak256(&add(&base, i));
            for k in 0..4 {
                let s = add(&d, k);
                data.push(json!({"slot": hx(&s), "word": hx(&r.word(token, &s)?)}));
            }
        }
        account.push(json!(hx(&w)));
    }
    Ok(json!({"family": "evm", "chainId": a.chain_id, "chainUid": hx(&chain_uid), "token": hx(&t), "block": r.block, "psid": hx(&psid),
        "ua": hx(ua), "account": account, "accountData": data}))
}

/// The holder's cache entry `<UA>:<token>` of the box file (clientkeys `openBalanceCache`; `state::open_cache_entry`):
/// `(balance, accSeq)` and the box.
fn cache_entry(path: &str, k: &ZetherKey<Bls12381>, token: &str) -> Result<(u64, u64, Value), String> {
    let b: Value = serde_json::from_slice(&std::fs::read(path).map_err(|e| format!("{path}: {e}"))?).map_err(|_| "--cache-box: JSON")?;
    let t: [u8; 20] = unhex(token)?.try_into().map_err(|_| "--token is 20 bytes")?;
    let (balance, seq) = state::open_cache_entry(k, &b, &t).map_err(|e| format!("--cache-box: {e}"))?;
    Ok((balance, seq, b))
}

fn table<C: ZCurve>(a: &Args) -> Result<BsgsTable<C>, String> {
    if let Some(path) = &a.table_file {
        if let Ok(bytes) = std::fs::read(path) {
            let t = BsgsTable::<C>::from_bytes(&bytes).map_err(|e| format!("{path}: {e}"))?;
            if t.table_bits() != a.table_bits {
                return Err(format!("{path} holds a 2^{} table, not 2^{}", t.table_bits(), a.table_bits));
            }
            return Ok(t);
        }
    }
    let t = BsgsTable::<C>::new(a.table_bits).map_err(|e| e.to_string())?;
    if let Some(path) = &a.table_file {
        std::fs::write(path, t.to_bytes()).map_err(|e| format!("{path}: {e}"))?;
    }
    Ok(t)
}

/// The words path: R1–R6 reads, then (R7: no request after this) the cache check or BSGS on the rebuilt ciphertext.
fn run_state(a: &Args, key_json: &Value) -> Result<Value, String> {
    let k = zether_prover::api::key::<Bls12381>(key_json)?;
    let cached = match (&a.cache_box, &a.token) {
        (Some(p), Some(t)) => Some(cache_entry(p, &k, t)?),
        _ => None,
    };
    if a.rpc.is_none() {
        let (balance, acc_seq, _) = cached.ok_or("no source")?;
        if a.pending {
            return Err("--pending needs --rpc (the cache holds acc only)".into());
        }
        return Ok(json!({"balance": balance.to_string(), "accSeq": acc_seq, "block": null, "source": "cache"}));
    }
    let mut v = read_words(a, &k.ua())?;
    let block = v["block"].clone();
    let mut rng = rand_core::OsRng;
    if let (Some((balance, seq, bx)), false) = (cached, a.pending) {
        v["cacheBox"] = bx;
        let ok = state::run(&state::prepare("checkBalance", &v, &k.y)?, &k, &mut rng)?;
        if ok["ok"] == true {
            return Ok(json!({"balance": balance.to_string(), "accSeq": seq, "block": block, "source": "cache+rpc"}));
        }
        v.as_object_mut().ok_or("words")?.remove("cacheBox");
    }
    let p = state::prepare(if a.pending { "pendingBalance" } else { "balance" }, &v, &k.y)?;
    let acc_seq = p.account().ok_or("no account")?.acc_seq;
    check_ram(a.table_bits, mem_available()).map_err(|e| e.to_string())?;
    let b = state::amount_with_table(&p, &k, &table::<Bls12381>(a)?, a.bound_bits)?;
    Ok(json!({"balance": b.to_string(), "accSeq": acc_seq, "block": block, "source": "rpc"}))
}

/// Feature `hazmat` only: a pasted `(C, D)` (spec §4.7: a ciphertext typed in by hand is chosen by whoever handed it over).
#[cfg(feature = "hazmat")]
fn run_pasted<C: ZCurve>(a: &Args, key_json: &Value) -> Result<Value, String> {
    use zether_prover::curve::decode_point;
    use zether_prover::elgamal::Ciphertext;
    let k = zether_prover::api::key::<C>(key_json)?;
    let point = |b: &[u8]| decode_point::<C>(b).map_err(|e| e.to_string());
    let (c, d) = a.ct.as_deref().ok_or("--ct")?.split_once(':').ok_or("--ct is <C hex>:<D hex>")?;
    let ct = Ciphertext { c: point(&unhex(c)?)?, d: point(&unhex(d)?)? };
    check_ram(a.table_bits, mem_available()).map_err(|e| e.to_string())?;
    let b = table::<C>(a)?.decrypt(&ct, &k.x, a.bound_bits).map_err(|e| e.to_string())?;
    Ok(json!({"balance": b.to_string(), "accSeq": null, "block": null, "source": "pasted"}))
}

fn run(a: &Args, req: &Value) -> Result<Value, String> {
    #[cfg(feature = "hazmat")]
    if a.ct.is_some() {
        return match a.curve.as_str() {
            #[cfg(feature = "bn254")]
            "bn254" => run_pasted::<Bn254>(a, req),
            "bls12381" => run_pasted::<Bls12381>(a, req),
            _ => Err("--curve must be bls12381 (bn254: legacy `bn254` feature)".into()),
        };
    }
    run_state(a, req)
}

fn main() -> ExitCode {
    let res = parse().and_then(|a| {
        if std::io::stdin().is_terminal() {
            return Err("pipe the key JSON on stdin (zether-read-balance … < key.json); a terminal would echo it".into());
        }
        let mut input = Zeroizing::new(String::new());
        std::io::stdin().read_to_string(&mut input).map_err(|e| e.to_string())?;
        let key: Value = serde_json::from_str(&input).map_err(|_| "stdin: key JSON expected".to_string())?;
        let mut req = Value::Object(serde_json::Map::from_iter([("key".to_string(), key)]));
        let out = run(&a, &req);
        wipe(&mut req);
        out
    });
    match res {
        Ok(v) => {
            println!("{v}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Overwrite every string in the parsed key JSON (review L3).
// ponytail: best effort — serde's parse buffers and any reallocation copies are not reachable;
// a non-Copy secret type end to end would need a custom deserializer.
fn wipe(v: &mut Value) {
    use zeroize::Zeroize;
    match v {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(wipe),
        Value::Object(o) => o.values_mut().for_each(wipe),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn curl_config_quotes_and_keeps_url_out_of_argv() {
        let c = curl_config("https://node/x?key=a\"b", r#"{"a":"\\"}"#);
        assert!(c.contains(r#"url = "https://node/x?key=a\"b""#), "{c}");
        assert!(c.contains(r#"data-binary = "{\"a\":\"\\\\\"}""#), "{c}");
        assert!(!curl_config("-o /tmp/x", "{}\nurl = \"evil\"").contains("\nurl = \"evil"), "no injected lines");
        let mut v: Value = serde_json::from_str(r#"{"key":{"x":"0x1234","n":[ "ab" ]}}"#).unwrap();
        wipe(&mut v);
        assert_eq!(v["key"]["x"], json!(""));
        assert_eq!(v["key"]["n"][0], json!(""));
        assert_eq!(add(&[0xff; 32], 1), [0; 32]);
    }
}
