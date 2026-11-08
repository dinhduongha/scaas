//! zether-read-balance — read a Zether balance too large for the wallet's device BSGS (lost cache
//! on a big account, zether-limits §4–§5). Native only. UNAUDITED.
//!
//!   zether-read-balance --curve bls12381 [--table-bits 24] [--bound-bits 54] [--table-file PATH] [--pending]
//!                       [--rpc <url> --chain-id <n> --chain-uid <genesis hash> --factory <address> --token <address>
//!                        (--depth <n> | --finalized)]
//!                       [--cache-box <file> --token <address>]
//!                       (feature `hazmat` only: --ct <C hex>:<D hex>)
//!   zether-read-balance --curve bls12381 --rpc … --chain-id … --chain-uid … --factory … --token … (--depth <n> | --finalized)
//!                       --registry <address> [--sync-block <n>]
//!                       (--decoy-count <n> --exclude <ua>,… [--recipient <ua>]
//!                        [--decoy-filter activity|holder --window <blocks>]
//!                        | --decoy-keys <ua>,…)                                       (decoys: no key, no stdin)
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
//!   R5: the token is catalogued by `--factory` (`OpenFactory._rec[token]`, the factory index's record at slot 8: `contractClass`
//!   TOKEN, `kind` a Zether kind; slot and packing held to ua-mtx-merge's pin `test/zether/ZetherStateVectors.t.sol`, T20b),
//!   and its code is a clone of a chain-neutral release with its `ChainEnv` (owner 2026-11-08). R6: the account read is
//!   `acct[UA(Y)]` of this key, computed here; a `--registry` (the decoy steps) is the one the token's `ChainEnv` names. R7: every read happens before the key is used,
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
//!
//! **Decoys** (CTR-UA-29, owner 2026-11-07; ua-rs-sign T15n) of a multi-recipient transfer on `--token`, in two steps around
//! `ua-rs`'s `pickDecoys` (this crate does not link `ua-rs`). The candidates are the registry's classical Zether list
//! (`uaAt(0x0141, i)`, `i < uaCount(0x0141)`), read from storage (`UAStore.Layout` slots 4 and 5) with R1–R5 as above; the
//! list's length is read at the sync point (`--sync-block`, at most the read block; default the read block), so a UA
//! registered later is never a candidate; everything else is read at the read block. `--decoy-count` prints `pickDecoys`'s
//! request `{candidates, exclude, count, weights?, recipient?}` (`--exclude`: the sender and every real recipient, named;
//! `--recipient`: the real recipient, excluded too, so that `pickDecoys` answers `legs`, the shuffled leg order to use) with
//! `syncBlock`, `listCount`, `block`, `blockHash`. Uniform by default; `--decoy-filter` (an option, off by default) keeps the
//! candidates active in the token in the last `--window` blocks by the account's counters word at `block − window`,
//! `block − window/2` and `block` (`activity`: any of `accSeq`, `pendingSeq`, `lastRolledPendingSeq`, `sendCounter` moved;
//! `holder`: `sendCounter` moved), weighted by recency (2 in the newer half, 1 in the older half only); the node must hold
//! those blocks' state. `--decoy-keys` (the UAs `pickDecoys` chose, with the same `--sync-block`) prints `{decoys: [{ua, yTo}]}`
//! (each a recipient with `amount` 0): each UA's record of kind `0x0141` (registry slot 0) with its list index below the
//! sync point's count and `uaAt` at that index equal to it, its `Y` from the record's SSTORE2 code, and `UA(Y)` equal to it.
//! The registry's slots 0, 4 and 5 are held to its layout pin, `test/ua/UAStoreLayout.t.sol` (T20b). Residuals:
//! `--registry` must be the generation that lists `0x0141` (a predecessor's list is not followed); the two steps are two reads
//! (each pinned to its own block; the sync point bounds both).

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
/// `OpenFactory._rec` (the factory index, ua-mtx-merge T67; slot 8, where `_info` was): three words `creatorId`, `ownerUA`,
/// `contractClass(16) ‖ kind(16) ‖ version(64) ‖ createdBlock(64) ‖ createdAt(64)` from the low end; held to its pin,
/// `test/zether/ZetherStateVectors.t.sol`, by `factory_record_is_the_layout_pin`. The Zether kinds (`IOpenFactory.TokenKind`
/// NORMAL_ZETHER, WRAPPED_ZETHER, NORMAL_ZETHER_REGULATED, WRAPPED_ZETHER_REGULATED).
const REC_SLOT: u64 = 8;
const CLASS_TOKEN: u16 = 1;
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
    registry: Option<String>,
    decoy_count: Option<u64>,
    decoy_keys: Option<Vec<[u8; 32]>>,
    exclude: Option<Vec<[u8; 32]>>,
    recipient: Option<[u8; 32]>,
    sync_block: Option<u64>,
    filter: Option<String>,
    window: Option<u64>,
}

impl Args {
    fn decoys(&self) -> bool {
        self.decoy_count.is_some() || self.decoy_keys.is_some()
    }
}

/// A comma-separated list of 32-byte UAs.
fn uas(f: &str, v: &str) -> Result<Vec<[u8; 32]>, String> {
    v.split(',').map(|u| unhex(u)?.try_into().map_err(|_| format!("{f}: 32 bytes each"))).collect()
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
            "--registry" => a.registry = Some(val()?),
            "--decoy-count" => a.decoy_count = Some(val()?.parse().map_err(|_| "--decoy-count: integer")?),
            "--decoy-keys" => a.decoy_keys = Some(uas("--decoy-keys", &val()?)?),
            "--exclude" => a.exclude = Some(uas("--exclude", &val()?)?),
            "--recipient" => a.recipient = Some(unhex(&val()?)?.try_into().map_err(|_| "--recipient: 32 bytes")?),
            "--sync-block" => a.sync_block = Some(val()?.parse().map_err(|_| "--sync-block: integer")?),
            "--decoy-filter" => {
                a.filter = Some(val()?).filter(|v| v == "activity" || v == "holder").ok_or("--decoy-filter: activity or holder")?.into()
            }
            "--window" => a.window = Some(val()?.parse().map_err(|_| "--window: integer")?),
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
    if a.decoys() {
        if a.rpc.is_none() || a.registry.is_none() || a.cache_box.is_some() || a.pending || pasted {
            return Err("decoys: --rpc and --registry, no --cache-box, --pending or --ct".into());
        }
        let candidates = a.decoy_count.is_some() && a.decoy_keys.is_none() && a.exclude.is_some() && a.filter.is_some() == a.window.is_some();
        let keys = a.decoy_keys.is_some() && a.decoy_count.is_none() && a.exclude.is_none() && a.recipient.is_none() && a.filter.is_none() && a.window.is_none();
        if !candidates && !keys {
            return Err("decoys: --decoy-count with --exclude (--recipient, and --decoy-filter with --window, or neither), or --decoy-keys alone".into());
        }
    } else if a.registry.is_some() || a.exclude.is_some() || a.recipient.is_some() || a.sync_block.is_some() || a.filter.is_some() || a.window.is_some() {
        return Err("--registry, --exclude, --recipient, --sync-block, --decoy-filter and --window go with --decoy-count or --decoy-keys".into());
    }
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
    fn code(&self, address: &[u8]) -> Result<Vec<u8>, String> {
        unhex(rpc(self.url, "eth_getCode", json!([hx(address), {"blockHash": self.hash}]))?.as_str().ok_or("eth_getCode: not bytes")?)
    }
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

/// R1, R2, R3 and R5: the configured chain's read block, the token catalogued with a Zether kind.
fn open(a: &Args) -> Result<Reader<'_>, String> {
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
    // `_rec[token]`'s word 2
    let rec = r.word(factory, &add(&keccak256(&[key, be(REC_SLOT)].concat()), 2))?;
    if !catalogued(&rec) {
        return Err("R5: the token is not a Zether token catalogued by this factory".into());
    }
    // R5, R6 (owner 2026-11-08): the token's code is a clone of a chain-neutral release; a `--registry` (the decoy steps) is the
    // one its `ChainEnv` names
    let env_registry = clone_registry(&r.code(&t)?).ok_or("R5: the token is not a clone of a chain-neutral release")?;
    if let Some(reg) = a.registry.as_deref() {
        if unhex(reg)? != env_registry {
            return Err("R6: --registry is not the token's registry".into());
        }
    }
    Ok(r)
}

/// The `registry` of a clone's `ChainEnv` when the code is exactly a clone of a chain-neutral release (chain-neutral spec §2;
/// ua-rs `factory::clone_env`, this crate does not link ua-rs): the 45-byte EIP-1167 proxy, `chainUid(32) ‖ registry(20) ‖
/// govRouter(20) ‖ smartKeyAccountImpl(20) ‖ hedera(1, 0 or 1) ‖ nDeps(1, ≤ 4) ‖ deps ‖ nParams(1, ≤ 2) ‖ params`, nothing after;
/// `None` for any other code. Held to `create3_kat.json` by `clone_registry_is_the_kat_layout`.
fn clone_registry(code: &[u8]) -> Option<[u8; 20]> {
    const HEAD: [u8; 10] = [0x36, 0x3d, 0x3d, 0x37, 0x3d, 0x3d, 0x3d, 0x36, 0x3d, 0x73];
    const TAIL: [u8; 15] = [0x5a, 0xf4, 0x3d, 0x82, 0x80, 0x3e, 0x90, 0x3d, 0x91, 0x60, 0x2b, 0x57, 0xfd, 0x5b, 0xf3];
    (code.get(..10)? == HEAD && code.get(30..45)? == TAIL && *code.get(137)? <= 1).then_some(())?;
    let deps = usize::from(*code.get(138)?);
    let at = 139 + 20 * deps;
    let params = usize::from(*code.get(at)?);
    (deps <= 4 && params <= 2 && code.len() == at + 1 + 32 * params).then_some(())?;
    code.get(77..97)?.try_into().ok()
}

/// `_rec[token]` word 2 names a token (class TOKEN; 0 is "not made here") of a Zether kind: `contractClass` the low 16 bits,
/// `kind` the next 16.
fn catalogued(rec: &[u8; 32]) -> bool {
    let class = u16::from_be_bytes([rec[30], rec[31]]);
    let kind = u16::from_be_bytes([rec[28], rec[29]]);
    class == CLASS_TOKEN && ZETHER_KINDS.iter().any(|k| u16::from(*k) == kind)
}

/// R1–R6: the words of `acct[ua]` of `token`, read at one final block of the configured chain from the one node, with the
/// location fields of `zether_prover::state`.
fn read_words(a: &Args, ua: &[u8; 32]) -> Result<Value, String> {
    let r = open(a)?;
    let token = a.token.as_deref().ok_or("--token")?;
    let chain_uid = unhex(a.chain_uid.as_deref().ok_or("--chain-uid")?)?;
    let t: [u8; 20] = unhex(token)?.try_into().map_err(|_| "--token: 20 bytes")?;
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

/// `UAStore.Layout` (the registry's storage at slot 0): `records` (slot 0), `uaCount` (slot 4), `uaAt` (slot 5); the classical
/// Zether list's key; the longest list read.
const REG_RECORDS_SLOT: u64 = 0;
const REG_COUNT_SLOT: u64 = 4;
const REG_AT_SLOT: u64 = 5;
const ZETHER_LIST: u64 = 0x0141;
const MAX_LIST: u64 = 50_000;

/// R3: block `n` still has `hash` (no reorg, a consistent node).
fn recheck(url: &str, n: u64, hash: &str) -> Result<(), String> {
    let again = rpc(url, "eth_getBlockByNumber", json!([format!("0x{n:x}"), false]))?;
    if again["hash"].as_str() != Some(hash) {
        return Err("R3: the block changed during the read (a reorg or an inconsistent node)".into());
    }
    Ok(())
}

/// Decoys (module doc): `pickDecoys`'s request (`--decoy-count`), or the chosen decoys' keys (`--decoy-keys`). No key.
fn decoys(a: &Args) -> Result<Value, String> {
    let (url, token, registry) = (a.rpc.as_deref().ok_or("--rpc")?, a.token.as_deref().ok_or("--token")?, a.registry.as_deref().ok_or("--registry")?);
    let r = open(a)?;
    let block = r.block;
    let mut pins = vec![(block, r.hash.clone())];
    // another block of the same chain, by hash, the node's answer checked (R3); re-checked after the last read
    let mut pin = |n: u64| -> Result<Reader<'_>, String> {
        let b = rpc(url, "eth_getBlockByNumber", json!([format!("0x{n:x}"), false]))?;
        if qty(&b["number"])? != n {
            return Err("R3: the node answered another block than the one asked for".into());
        }
        let hash = b["hash"].as_str().ok_or("R3: no block hash")?.to_string();
        pins.push((n, hash.clone()));
        Ok(Reader { url, block: n, hash })
    };
    let sync = a.sync_block.unwrap_or(block);
    if sync > block {
        return Err("--sync-block is past the read block".into());
    }
    let n = pin(sync)?.word(registry, &keccak256(&[be(ZETHER_LIST), be(REG_COUNT_SLOT)].concat()))?;
    let n = (n[..24] == [0; 24]).then(|| u64::from_be_bytes(n[24..].try_into().unwrap_or_default())).filter(|n| *n <= MAX_LIST)
        .ok_or("the registry's list is longer than this tool reads")?;
    let list = keccak256(&[be(ZETHER_LIST), be(REG_AT_SLOT)].concat());
    let mut out = if let Some(keys) = &a.decoy_keys {
        let mut legs = Vec::new();
        for ua in keys {
            // `Record`: `kind(16) ‖ registeredAt(40) ‖ keyPtr(160) ‖ index(40)` from the low end; the code `0x00 ‖ Y`
            let rec = r.word(registry, &keccak256(&[*ua, be(REG_RECORDS_SLOT)].concat()))?;
            let index = rec[..5].iter().fold(0u64, |x, b| x << 8 | u64::from(*b));
            let listed = rec[30..] == [0x01, 0x41] && index < n && r.word(registry, &keccak256(&[be(index), list].concat()))? == *ua;
            let code = if listed { r.code(&rec[5..25])? } else { Vec::new() };
            let y = match code.split_first() {
                Some((0, y)) => zether_prover::curve::decode_point::<Bls12381>(y).ok().filter(|p| zether_prover::curve::ua_of::<Bls12381>(p) == *ua),
                _ => None,
            };
            if y.is_none() {
                return Err(format!("{} is not a registered Zether UA on the 0x0141 list up to the sync point", hx(ua)));
            }
            legs.push(json!({"ua": hx(ua), "yTo": hx(&code[1..])}));
        }
        json!({"decoys": legs})
    } else {
        let mut exclude = a.exclude.clone().unwrap_or_default();
        exclude.extend(a.recipient);
        let mut candidates: Vec<[u8; 32]> = Vec::new();
        for i in 0..n {
            let u = r.word(registry, &keccak256(&[be(i), list].concat()))?;
            if !candidates.contains(&u) && !exclude.contains(&u) {
                candidates.push(u);
            }
        }
        let mut request = json!({"exclude": exclude.iter().map(|u| hx(u)).collect::<Vec<_>>(), "count": a.decoy_count});
        if let Some(u) = a.recipient {
            request["recipient"] = json!(hx(&u));
        }
        if let Some(w) = a.window {
            let old = block.checked_sub(w).filter(|_| w >= 2).ok_or("--window: at least 2 and at most the read block")?;
            let (old, mid) = (pin(old)?, pin(block - w / 2)?);
            let (_, _, inner, byte, width) = *state::LAYOUT.iter().find(|l| l.0 == "acct[U].sendCounter").ok_or("layout")?;
            let sent = |w: &[u8; 32]| w[32 - byte - width..32 - byte].to_vec();
            // the counters word (`accSeq ‖ pendingSeq ‖ lastRolledPendingSeq ‖ sendCounter`): any move, or `holder`: `sendCounter`
            let moved = |x: &Reader, y: &Reader, slot: &[u8; 32]| -> Result<bool, String> {
                let (x, y) = (x.word(token, slot)?, y.word(token, slot)?);
                Ok(if a.filter.as_deref() == Some("holder") { sent(&x) != sent(&y) } else { x != y })
            };
            let (mut kept, mut weights) = (Vec::new(), Vec::new());
            for u in candidates {
                let slot = add(&keccak256(&[u, add(&state::ROOT, 8)].concat()), inner);
                let w = if moved(&mid, &r, &slot)? { 2 } else if moved(&old, &mid, &slot)? { 1 } else { 0 };
                if w > 0 {
                    kept.push(u);
                    weights.push(w);
                }
            }
            candidates = kept;
            request["weights"] = json!(weights);
        }
        request["candidates"] = json!(candidates.iter().map(|u| hx(u)).collect::<Vec<_>>());
        json!({"request": request})
    };
    for (b, h) in &pins {
        recheck(url, *b, h)?;
    }
    for (k, v) in [("syncBlock", json!(sync)), ("listCount", json!(n)), ("block", json!(block)), ("blockHash", json!(r.hash))] {
        out[k] = v;
    }
    Ok(out)
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
        if a.decoys() {
            return decoys(&a);
        }
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

    /// T20b second sync (T15m2): `OpenFactory._rec[token]` (the factory index, ua-mtx-merge T67) is read where its pin puts it,
    /// `test/zether/ZetherStateVectors.t.sol`: slot `REC`, word 2 (`base + 2`), from the low end `contractClass(16) ‖ kind(16) ‖
    /// version(64)`; R5 takes class TOKEN with one of this reader's kinds, never the old one-word `_info` packing.
    #[test]
    fn factory_record_is_the_layout_pin() {
        let pin = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../smartcontracts/evm/test/zether/ZetherStateVectors.t.sol"))
            .unwrap();
        for a in [
            &format!("uint256 internal constant REC = {REC_SLOT};")[..],
            "uint256 base = uint256(keccak256(abi.encode(address(tok), REC)));",
            "vm.load(address(factory), bytes32(base + 2)));",
            r#"assertEq(uint16(uint256(r2)), 1, "_rec[token].contractClass (TOKEN)");"#,
            "assertEq(uint16(uint256(r2) >> 16), ",
            r#"assertEq(uint64(uint256(r2) >> 32), 1, "_rec[token].version");"#,
        ] {
            assert!(pin.contains(a), "the pin moved: {a}");
        }
        let word = |class: u8, kind: u8| {
            let mut w = [0u8; 32];
            (w[31], w[29], w[27]) = (class, kind, 1);
            w
        };
        assert!(catalogued(&word(1, ZETHER_KINDS[0])), "positive control");
        assert!(ZETHER_KINDS.iter().all(|k| catalogued(&word(1, *k))), "every kind of this reader");
        assert!(!catalogued(&word(0, ZETHER_KINDS[0])), "class 0: not made here");
        assert!(!catalogued(&word(2, ZETHER_KINDS[0])), "class DEX");
        assert!(!catalogued(&word(1, 4)), "the other confidential family");
        let mut wide = word(1, ZETHER_KINDS[0]);
        wide[28] = 1; // kind 256 + k: a uint16 kind, not its low byte
        assert!(!catalogued(&wide), "the kind's high byte");
        let mut old = [0u8; 32];
        (old[2], old[11]) = (1, ZETHER_KINDS[0]); // `_info`: exists, kind
        assert!(!catalogued(&old), "the old one-word packing");
    }

    /// Owner 2026-11-08: the `ChainEnv` layout of `create3_kat.json`: each KAT clone (its init code less the 10-byte prefix) gives
    /// its env's registry; another proxy byte, a byte short or long, five deps or the proxy alone give none.
    #[test]
    fn clone_registry_is_the_kat_layout() {
        let kat: Value = serde_json::from_str(&std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"),
            "/../../smartcontracts/vectors/factory/create3_kat.json")).unwrap()).unwrap();
        for e in kat["envs"].as_array().unwrap() {
            let init = unhex(e["cloneInitCode"].as_str().unwrap()).unwrap();
            let env = unhex(e["env"].as_str().unwrap()).unwrap();
            let rt = &init[10..];
            assert_eq!(clone_registry(rt).map(|r| r.to_vec()), Some(env[32..52].to_vec()), "{}", e["name"]);
            let mut x = rt.to_vec();
            x[0] ^= 1;
            assert_eq!(clone_registry(&x), None, "another head");
            let mut x = rt.to_vec();
            x[44] ^= 1;
            assert_eq!(clone_registry(&x), None, "another tail");
            assert_eq!(clone_registry(&rt[..rt.len() - 1]), None, "a byte short");
            assert_eq!(clone_registry(&[rt, &[0][..]].concat()), None, "a byte long");
            assert_eq!(clone_registry(&rt[..45]), None, "the proxy alone");
        }
        let rt = &unhex(kat["envs"][0]["cloneInitCode"].as_str().unwrap()).unwrap()[10..];
        let mut five = rt.to_vec();
        five[138] = 5;
        five.splice(139..139, [0u8; 100]);
        assert_eq!(clone_registry(&five), None, "five deps");
        let mut hedera = rt.to_vec();
        hedera[137] = 2;
        assert_eq!(clone_registry(&hedera), None, "hedera 2");
    }

    /// The slot the registry's layout pin gives `field`: its probe writes one field per slot, `s.<field>…; // <slot>`.
    fn pin_slot(pin: &str, field: &str) -> Option<u64> {
        pin.lines().find_map(|l| {
            let rest = l.trim().strip_prefix("s.")?.strip_prefix(field)?;
            rest.starts_with(['[', '.', ' ']).then_some(())?;
            rest.rsplit_once("// ")?.1.split_whitespace().next()?.parse().ok()
        })
    }

    /// T20b second sync: the registry slots of the decoy steps are the layout pin's (`UAStore.Layout`, ua-mtx-merge's
    /// `test/ua/UAStoreLayout.t.sol`), as `pqz-read`'s are.
    #[test]
    fn registry_slots_are_the_layout_pin() {
        let pin = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../smartcontracts/evm/test/ua/UAStoreLayout.t.sol"))
            .unwrap();
        for (field, slot) in [("records", REG_RECORDS_SLOT), ("uaCount", REG_COUNT_SLOT), ("uaAt", REG_AT_SLOT)] {
            assert_eq!(pin_slot(&pin, field), Some(slot), "{field}");
        }
    }
}
