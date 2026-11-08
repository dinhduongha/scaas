// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! pqz-read — the PQZ reference reading layer (ARCH-POS-13, "never a decryption oracle"; spec no-decryption-oracle §4.2 R1–R7,
//! §4.3, §4.12; ua-rs-sign T15m, owner 2026-11-07). The PQZ twin of `zether-read-balance --rpc`. Native only. UNAUDITED.
//!
//!   pqz-read --rpc <url> --chain-id <n> --chain-uid <genesis hash> --factory <address> --registry <address> --token <address>
//!            --ua <bytes32> (--depth <n> | --finalized)
//!            [--command balance] --key-version <v> --for-op7 <true|false>               (the holder's own balance of version v)
//!            --command auditRead --key-version <v> --from-ua <bytes32> --send-counter <n> --leg <j>
//!                                                                     (an audited leg, the token's auditor at its version v)
//!            [--words]                                                                  (print the request read; no key)
//!            --command decoys --count <n> [--exclude <ua>,…] [--recipient <ua>] [--sync-block <n>]   (op 7's decoys; no key,
//!            [--decoy-filter activity|holder --window <blocks>] [--words]                              no stdin)
//!
//! The key is read from **stdin** as JSON, `{"mnemonic": "…", "passphrase"?: "…", "account": n, "index": n}` (the handle
//! `Wallet::pqz_key_version(account, index, --key-version)`), piped from a file; a terminal on stdin is refused. It never
//! leaves this process. Group 3g (ua-rs-sign T15o): `--key-version` names the PQZ key version read, no default; a balance over
//! every version is the sum of one call per version (`pqzVersions[--ua].latest` says how many), the debited version a debit's.
//!
//! This tool reads the raw storage words a `ua-rs` PQZ words command takes and feeds them to `ua-rs` (it never parses a
//! ciphertext or decrypts itself), as a reading layer meeting R1 to R7:
//! - **R1** `--rpc` is the one source of every word, a node the holder names here (their own, or one they configured): never a
//!   default or a discovered endpoint. The URL and body go to `curl` on its stdin (`--config -`, `-q` first), never in argv.
//! - **R2** `eth_chainId` and `eth_getBlockByNumber("0x0").hash` must equal `--chain-id` and `--chain-uid` (NET-ALL-22).
//! - **R3** one block: the chain's `finalized` block (`--finalized`) or `head − depth` (`--depth`, NET-EVM-04); every read
//!   names it by hash (EIP-1898, `requireCanonical`); the node must answer the block asked for, and the same number must still
//!   carry the same hash after the last read (else the read is refused: a reorg or an inconsistent node).
//! - **R4** storage only: `eth_getStorageAt` and `eth_getCode` at that block, no view. (`keccak256(code) == codeHash` is not
//!   checked: no `eth_getProof`; a residual, as in `zether-read-balance`.)
//! - **R5** the token is catalogued by `--factory` with a PQZ kind (`OpenFactory._rec[token]`, the factory index's record at
//!   slot 8: `contractClass` TOKEN, `kind` NORMAL_PQZ, WRAPPED_PQZ, NORMAL_PQZ_REGULATED or WRAPPED_PQZ_REGULATED), its slot
//!   and packing held to their pin, ua-mtx-merge's `test/zether/ZetherStateVectors.t.sol` (T20b, T15m2).
//! - **R6** `keyRecord` is `--registry`'s `pqzKey[--ua][--key-version]` (`UAStore.Layout` slot 2, per version) and its code
//!   must hold this handle's key; `keyVersions` its `pqzVersions[--ua]` (slot 17: `latest ‖ current ‖ listed`, which `ua-rs`
//!   checks against `--key-version`); for `auditRead` `--ua` must be the token's `auditorUA` and its `auditorMode` not NONE
//!   (`ua-rs` checks the entry's copy; a copy made under another auditor version is found by trying each).
//! - **R7** every read, the R3 re-check included, happens before the key is used; nothing after it goes back to the node.
//!
//! The token's slots come from `ua-rs`'s [`STATE_LAYOUT`] (T19c's pin of `scaas.pqz`, compared with the pin by the facade's
//! tests) under the ERC-7201 root of `scaas.pqz`; the words read are exactly those [`STATE_LAYOUT`] lists for the command.
//! Prints `ua-rs`'s answer with `block` and `blockHash` (`--words`: `{command, request, block, blockHash}`).
//!
//! **`decoys`** (CTR-UA-29, owner 2026-11-07; ua-rs-sign T15n): the decoys of an op 7 by `--ua` on `--token`. The candidates are
//! the registry's PQZ-capable list (`uaAt(0x0142, i)`, `i < uaCount(0x0142)`), read from storage (`UAStore.Layout` slots 4
//! and 5); the list's length is read at the sync point (`--sync-block`, at most the read block; default the read block), so a
//! UA registered later is never a candidate; everything else is read at the read block. `--ua` and every `--exclude` (the real
//! recipients) are excluded; `--recipient` (the real recipient, excluded too) goes to the pick, which then shuffles the
//! legs (below). By default the pick is uniform; `--decoy-filter` (an option, off by default) keeps only the
//! candidates active in the token in the last `--window` blocks, by the account's counters at `block − window`,
//! `block − window/2` and `block` (`activity`: `pendingCount`, `rolled` or `sendCounter` moved, i.e. a pending entry, a
//! rollover or a debit; `holder`: `sendCounter` moved, a holder-authorised debit), weighted by recency (2 when active in the
//! newer half, 1 when only in the older half); the node must hold the state of those blocks. **Never a UA with a pending key
//! version** (group 3g KV-7, R3, F-2; T15o): a candidate whose `pqzVersions.latest` is above `current` with a key of this set's
//! length (its proof bytes are missing: an imminent rotation, a credit to it would fail) is dropped before the pick, as
//! clientkeys `pqzDecoyCandidates`. The candidates go to `ua-rs`'s `pickDecoys` (`facade::decoys`, the OS CSPRNG), then each
//! chosen decoy's key is read at its current version: `pqzKey[ua][current]` (proven) and its SSTORE2 code. Prints `{decoys: [{ua, pk}], syncBlock, listCount, block, blockHash}` (each an op 7 leg with `amount` 0), with
//! `--recipient` also `legs`, the full leg order (the recipient and the decoys' UAs, uniformly shuffled by the OS CSPRNG): the
//! caller builds op 7's legs in that order (a fixed position names the recipient); `--words`
//! prints `pickDecoys`'s request instead (`{command, request, syncBlock, listCount, block, blockHash}`). The registry's slots 2,
//! 4, 5 and 17 are held to its layout pin, `test/ua/UAStoreLayout.t.sol` (T20b). Residuals: `--registry`
//! must be the generation that lists `0x0142` (a predecessor's list and records are not followed); the activity filter reads
//! each candidate's account at its current version of the read block; clientkeys' preference for UAs without a recent
//! `UAPqzKeyCurrent` is not applied (no event reads: storage only, R4).

use std::io::{IsTerminal, Read};
use std::process::{Command, ExitCode, Stdio};

use pqz_ffi::pqzl::PK_BYTES;
use pqz_ffi::stmt::{K_MAX, PQZH_ID};
use scaas_ua::facade::pqz::STATE_LAYOUT;
use scaas_ua::facade::pqz_pack::ACC_WORDS;
use scaas_ua::keccak256;
use serde_json::{json, Value};
use zeroize::{Zeroize, Zeroizing};

type Word = [u8; 32];

/// `OpenFactory._rec` (the factory index, ua-mtx-merge T67; slot 8, where `_info` was): three words `creatorId`, `ownerUA`,
/// `contractClass(16) ‖ kind(16) ‖ version(64) ‖ createdBlock(64) ‖ createdAt(64)` from the low end; held to its pin,
/// `test/zether/ZetherStateVectors.t.sol`, by `factory_record_is_the_layout_pin`. The PQZ kinds (`IOpenFactory.TokenKind`).
const REC_SLOT: u64 = 8;
const CLASS_TOKEN: u16 = 1;
const PQZ_KINDS: [u8; 4] = [4, 5, 12, 13];
/// `UAStore.Layout.pqzKey` (the registry's slot 2, keyed `(ua, version)` since group 3g): `ptr(160) ‖ proven(8) ‖ added(8)`;
/// `pqzVersions` (slot 17): `latest(64) ‖ current(64) ‖ listed(8)`. These and `uaCount` / `uaAt` below are the registry's layout
/// pin's (`smartcontracts/evm/test/ua/UAStoreLayout.t.sol`), held to it by `registry_slots_are_the_layout_pin`.
const REG_PQZ_KEY_SLOT: u64 = 2;
const REG_PQZ_VERSIONS_SLOT: u64 = 17;
/// `PqzCore.INLINE_MAX`, `INLINE_MAX_PQZH` (op 7 of a PQZH token): the facade's `p` rule (CTR-PQZ-06).
const INLINE_MAX: u64 = 16;
const INLINE_MAX_PQZH: u64 = 10;
/// A node's answer is at most this long (a blob's code is far below).
const MAX_ANSWER: u64 = 16 << 20;
/// `UAStore.Layout` (the registry's storage at slot 0): `uaCount` (slot 4), `uaAt` (slot 5); the PQZ-capable list's key.
const REG_COUNT_SLOT: u64 = 4;
const REG_AT_SLOT: u64 = 5;
const PQZ_LIST: u64 = 0x0142;
/// The longest list read (one word per UA; `facade::decoys::MAX` holds about 55,000).
const MAX_LIST: u64 = 50_000;

#[derive(Default)]
struct Args {
    rpc: String,
    chain_id: u64,
    chain_uid: Word,
    factory: [u8; 20],
    registry: [u8; 20],
    token: [u8; 20],
    ua: Word,
    depth: Option<u64>,
    finalized: bool,
    command: String,
    for_op7: Option<bool>,
    key_version: Option<u64>,
    from_ua: Option<Word>,
    send_counter: Option<u64>,
    leg: Option<u64>,
    words: bool,
    count: Option<u64>,
    exclude: Vec<Word>,
    recipient: Option<Word>,
    sync_block: Option<u64>,
    filter: Option<String>,
    window: Option<u64>,
}

fn unhex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim().strip_prefix("0x").unwrap_or(s.trim());
    if !s.len().is_multiple_of(2) {
        return Err(format!("not hex: {s}"));
    }
    (0..s.len()).step_by(2).map(|i| s.get(i..i + 2).and_then(|b| u8::from_str_radix(b, 16).ok()).ok_or(format!("not hex: {s}"))).collect()
}

fn hx(b: &[u8]) -> String {
    b.iter().fold(String::from("0x"), |s, x| s + &format!("{x:02x}"))
}

fn fixed<const L: usize>(flag: &str, s: &str) -> Result<[u8; L], String> {
    unhex(s)?.try_into().map_err(|_| format!("{flag}: {L} bytes"))
}

fn parse() -> Result<Args, String> {
    let mut a = Args { command: "balance".into(), ..Args::default() };
    let mut seen = std::collections::BTreeSet::new();
    let mut it = std::env::args().skip(1);
    while let Some(f) = it.next() {
        if !seen.insert(f.clone()) {
            return Err(format!("{f} given twice"));
        }
        let mut val = || it.next().ok_or(format!("{f} needs a value"));
        let int = |v: String| v.parse::<u64>().map_err(|_| format!("{f}: integer"));
        match f.as_str() {
            "--rpc" => a.rpc = val()?,
            "--chain-id" => a.chain_id = int(val()?)?,
            "--chain-uid" => a.chain_uid = fixed("--chain-uid", &val()?)?,
            "--factory" => a.factory = fixed("--factory", &val()?)?,
            "--registry" => a.registry = fixed("--registry", &val()?)?,
            "--token" => a.token = fixed("--token", &val()?)?,
            "--ua" => a.ua = fixed("--ua", &val()?)?,
            "--depth" => a.depth = Some(int(val()?)?),
            "--finalized" => a.finalized = true,
            "--command" => a.command = val()?,
            "--for-op7" => a.for_op7 = Some(val()?.parse().map_err(|_| "--for-op7: true or false")?),
            "--key-version" => a.key_version = Some(int(val()?)?),
            "--from-ua" => a.from_ua = Some(fixed("--from-ua", &val()?)?),
            "--send-counter" => a.send_counter = Some(int(val()?)?),
            "--leg" => a.leg = Some(int(val()?)?),
            "--words" => a.words = true,
            "--count" => a.count = Some(int(val()?)?),
            "--exclude" => a.exclude = val()?.split(',').map(|u| fixed("--exclude", u)).collect::<Result<_, _>>()?,
            "--recipient" => a.recipient = Some(fixed("--recipient", &val()?)?),
            "--sync-block" => a.sync_block = Some(int(val()?)?),
            "--decoy-filter" => a.filter = Some(val()?).filter(|v| v == "activity" || v == "holder").ok_or("--decoy-filter: activity or holder")?.into(),
            "--window" => a.window = Some(int(val()?)?),
            _ => return Err(format!("unknown argument {f}")),
        }
    }
    let need = ["--rpc", "--chain-id", "--chain-uid", "--factory", "--registry", "--token", "--ua"];
    if need.iter().any(|n| !seen.contains(*n)) || a.finalized == a.depth.is_some() {
        return Err("needs --rpc, --chain-id, --chain-uid, --factory, --registry, --token, --ua and one of --depth / --finalized (R1–R6)".into());
    }
    let entry = u8::from(a.from_ua.is_some()) + u8::from(a.send_counter.is_some()) + u8::from(a.leg.is_some());
    let decoy = ["--count", "--exclude", "--recipient", "--sync-block", "--decoy-filter", "--window"].iter().any(|f| seen.contains(*f));
    if decoy && a.command != "decoys" {
        return Err("--count, --exclude, --recipient, --sync-block, --decoy-filter and --window go with --command decoys only".into());
    }
    match a.command.as_str() {
        "decoys" if a.for_op7.is_none() && a.key_version.is_none() && entry == 0 && a.count.is_some() && a.filter.is_some() == a.window.is_some() => {}
        "decoys" => return Err("decoys needs --count, --decoy-filter with --window or neither, and no --for-op7, --key-version or entry fields".into()),
        "balance" if a.for_op7.is_some() && a.key_version.is_some() && entry == 0 => {}
        "balance" => return Err("balance needs --key-version <v>, --for-op7 <true|false> and no entry fields".into()),
        "auditRead" if a.for_op7.is_none() && a.key_version.is_some() && entry == 3 => {}
        "auditRead" => return Err("auditRead needs --key-version, --from-ua, --send-counter and --leg (no --for-op7)".into()),
        c => return Err(format!("--command {c}: balance or auditRead, or decoys")),
    }
    Ok(a)
}

/// A curl config file (read from curl's stdin): URL and body stay out of argv.
fn curl_config(url: &str, body: &str) -> String {
    let q = |s: &str| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"").replace(['\n', '\r'], ""));
    format!(
        "silent\nshow-error\nmax-filesize = {MAX_ANSWER}\nrequest = \"POST\"\nheader = \"content-type: application/json\"\nurl = {}\ndata-binary = {}\n",
        q(url),
        q(body)
    )
}

/// One JSON-RPC call to the one source (R1), through `curl`.
fn rpc(url: &str, method: &str, params: Value) -> Result<Value, String> {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    let mut child = Command::new("curl")
        .args(["-q", "--config", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| format!("curl: {e}"))?;
    let mut stdin = child.stdin.take().ok_or("curl: no stdin")?;
    std::io::Write::write_all(&mut stdin, curl_config(url, &body.to_string()).as_bytes()).map_err(|e| e.to_string())?;
    drop(stdin);
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    let v: Value = serde_json::from_slice(&out.stdout).map_err(|_| format!("{method}: the node returned no JSON"))?;
    v.get("result").filter(|r| !r.is_null()).cloned().ok_or(format!("{method}: {}", v["error"]))
}

fn qty(v: &Value) -> Result<u64, String> {
    u64::from_str_radix(v.as_str().ok_or("a quantity expected")?.trim_start_matches("0x"), 16).map_err(|_| "a quantity expected".into())
}

/// `a + i` (mod 2^256), big-endian.
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

fn addr_word(a: &[u8; 20]) -> Word {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}

/// ERC-7201: `keccak256(abi.encode(uint256(keccak256(id)) − 1)) & ~0xff`.
fn erc7201(id: &str) -> Word {
    let h = keccak256(id.as_bytes());
    let mut m = h;
    for b in m.iter_mut().rev() {
        let borrow = *b == 0;
        *b = b.wrapping_sub(1);
        if !borrow {
            break;
        }
    }
    let mut r = keccak256(&m);
    r[31] = 0;
    r
}

/// `STATE_LAYOUT`'s `(slot, inner, byte, width)` of `label` (the pinned layout of `scaas.pqz`).
fn at(label: &str) -> Result<(u64, u64, usize, usize), String> {
    STATE_LAYOUT.iter().find(|r| r.0 == label).map(|r| (r.1, r.2, r.3, r.4)).ok_or(format!("{label}: not in STATE_LAYOUT"))
}

/// The field `label` of word `w` (bytes counted from the low end, solc's packing), as an integer (width ≤ 8).
fn field(w: &Word, label: &str) -> Result<u64, String> {
    let (_, _, byte, width) = at(label)?;
    Ok(w[32 - byte - width..32 - byte].iter().fold(0u64, |a, b| a << 8 | u64::from(*b)))
}

fn low_addr(w: &Word, byte: usize) -> [u8; 20] {
    let mut a = [0u8; 20];
    a.copy_from_slice(&w[32 - byte - 20..32 - byte]);
    a
}

/// `acct[ua][v]` of `scaas.pqz` (group 3g KV-6): `keccak256(v ‖ keccak256(ua ‖ root + slot))`.
fn acct_base(root: &Word, ua: &Word, v: u64) -> Result<Word, String> {
    Ok(keccak256(&[be(v), keccak256(&[*ua, add(root, at("acct[U][7].pendingCount")?.0)].concat())].concat()))
}

/// `sendCounter[ua]` of `scaas.pqz` (one per UA since group 3g).
fn counter_slot(root: &Word, ua: &Word) -> Result<Word, String> {
    Ok(keccak256(&[*ua, add(root, at("sendCounter[U]")?.0)].concat()))
}

/// The registry's `pqzKey[ua][v]` and `pqzVersions[ua]`.
fn pqz_key_slot(ua: &Word, v: u64) -> Word {
    keccak256(&[be(v), keccak256(&[*ua, be(REG_PQZ_KEY_SLOT)].concat())].concat())
}
fn versions_slot(ua: &Word) -> Word {
    keccak256(&[*ua, be(REG_PQZ_VERSIONS_SLOT)].concat())
}

/// The words of one block (R3), by hash (EIP-1898), storage and code only (R4), from the one source (R1).
struct Reader<'a> {
    url: &'a str,
    hash: String,
}

impl Reader<'_> {
    fn at(&self) -> Value {
        json!({"blockHash": self.hash, "requireCanonical": true})
    }
    fn word(&self, address: &[u8; 20], slot: &Word) -> Result<Word, String> {
        let w = rpc(self.url, "eth_getStorageAt", json!([hx(address), hx(slot), self.at()]))?;
        let b = unhex(w.as_str().ok_or("eth_getStorageAt: not a word")?)?;
        let mut o = [0u8; 32];
        o.get_mut(32usize.checked_sub(b.len()).ok_or("eth_getStorageAt: longer than a word")?..)
            .ok_or("word")?
            .copy_from_slice(&b);
        Ok(o)
    }
    fn code(&self, address: &[u8; 20]) -> Result<Vec<u8>, String> {
        unhex(rpc(self.url, "eth_getCode", json!([hx(address), self.at()]))?.as_str().ok_or("eth_getCode: not bytes")?)
    }
    /// `{address, code}` of each pointer, each once, in order of first use.
    fn blobs(&self, ptrs: &[[u8; 20]]) -> Result<Vec<Value>, String> {
        let mut seen: Vec<[u8; 20]> = Vec::new();
        let mut out = Vec::new();
        for p in ptrs {
            if !seen.contains(p) {
                seen.push(*p);
                out.push(json!({"address": hx(p), "code": hx(&self.code(p)?)}));
            }
        }
        Ok(out)
    }
}

/// The request's words, read under R1–R6 at one block (R3), with the registered key's code (for R6's key check).
struct Words {
    request: Value,
    block: u64,
    hash: String,
    key_code: Vec<u8>,
}

/// R2, R3 and R5: the configured chain, its read block (by hash), the token catalogued with a PQZ kind.
fn open(a: &Args) -> Result<(Reader<'_>, u64), String> {
    let url = a.rpc.as_str();
    // R2
    if qty(&rpc(url, "eth_chainId", json!([]))?)? != a.chain_id {
        return Err("R2: eth_chainId is not the configured chain".into());
    }
    let genesis = rpc(url, "eth_getBlockByNumber", json!(["0x0", false]))?;
    if unhex(genesis["hash"].as_str().ok_or("R2: no genesis hash")?)? != a.chain_uid {
        return Err("R2: the genesis hash is not the configured chain_uid".into());
    }
    // R3
    let (tag, want) = match a.depth {
        Some(d) => {
            let n = qty(&rpc(url, "eth_blockNumber", json!([]))?)?.checked_sub(d).ok_or("R3: the chain is shorter than the confirmation depth")?;
            (format!("0x{n:x}"), Some(n))
        }
        None => ("finalized".to_string(), None),
    };
    let b = rpc(url, "eth_getBlockByNumber", json!([tag, false]))?;
    let block = qty(&b["number"])?;
    if want.is_some_and(|n| n != block) {
        return Err("R3: the node answered another block than the one asked for".into());
    }
    let r = Reader { url, hash: b["hash"].as_str().ok_or("R3: no block hash")?.to_string() };
    // R5: `_rec[token]`'s word 2
    let rec = r.word(&a.factory, &add(&keccak256(&[addr_word(&a.token), be(REC_SLOT)].concat()), 2))?;
    if !catalogued(&rec) {
        return Err("R5: the token is not a PQZ token catalogued by this factory".into());
    }
    Ok((r, block))
}

/// `_rec[token]` word 2 names a token (class TOKEN; 0 is "not made here") of a PQZ kind: `contractClass` the low 16 bits, `kind`
/// the next 16.
fn catalogued(rec: &Word) -> bool {
    let class = u16::from_be_bytes([rec[30], rec[31]]);
    let kind = u16::from_be_bytes([rec[28], rec[29]]);
    class == CLASS_TOKEN && PQZ_KINDS.iter().any(|k| u16::from(*k) == kind)
}

/// R3: block `n` still has `hash` (no reorg, a consistent node).
fn recheck(url: &str, n: u64, hash: &str) -> Result<(), String> {
    let again = rpc(url, "eth_getBlockByNumber", json!([format!("0x{n:x}"), false]))?;
    if again["hash"].as_str() != Some(hash) {
        return Err("R3: the block changed during the read (a reorg or an inconsistent node)".into());
    }
    Ok(())
}

fn read(a: &Args) -> Result<Words, String> {
    let url = a.rpc.as_str();
    let (r, block) = open(a)?;
    // R4, R6: the token's words by the pinned layout, the registry's key record of --ua
    let root = erc7201("scaas.pqz");
    let tok = |label: &str| -> Result<Word, String> { r.word(&a.token, &add(&root, at(label)?.0)) };
    let psid = tok("psid")?;
    let v = a.key_version.ok_or("--key-version")?;
    let key_record = r.word(&a.registry, &pqz_key_slot(&a.ua, v))?;
    let key_ptr = low_addr(&key_record, 0);
    let mut request = json!({"chainUid": hx(&a.chain_uid), "token": hx(&a.token), "block": block, "psid": hx(&psid),
        "keyRecord": hx(&key_record), "ua": hx(&a.ua)});
    let blobs = if a.command == "balance" {
        let base = acct_base(&root, &a.ua, v)?;
        let account = (0..3).map(|i| r.word(&a.token, &add(&base, i))).collect::<Result<Vec<_>, _>>()?;
        let (s0, s1) = (&account[0], &account[1]);
        let (count, rolled) = (field(s0, "acct[U][7].pendingCount")?, field(s0, "acct[U][7].rolled")?);
        let (units, flags) = (field(s1, "acct[U][7].accUnits")?, field(s1, "acct[U][7].flags")?);
        let acc_blob = low_addr(s1, at("acct[U][7].accBlob")?.2);
        let mut ptrs = vec![key_ptr];
        let mut acc_words = Vec::new();
        if flags & 1 != 0 {
            let first = add(&base, at("acct[U][7].accWords[0]")?.1);
            for i in 0..ACC_WORDS as u64 {
                acc_words.push(json!(hx(&r.word(&a.token, &add(&first, i))?)));
            }
        } else if acc_blob != [0; 20] {
            ptrs.push(acc_blob);
        }
        // the facade's `p` (CTR-PQZ-06): the pending window `[rolled, p)` is read by index only
        let room = (K_MAX as u64).checked_sub(units + 1).ok_or("the account's accUnits are past K_MAX")?;
        let inline = if a.for_op7 == Some(true) && psid == PQZH_ID { INLINE_MAX_PQZH } else { INLINE_MAX };
        let p = count.min(rolled.saturating_add(inline.min(room)));
        let map = add(&base, at("acct[U][7].pending[3]")?.1);
        let mut pending = Vec::new();
        for i in rolled..p {
            let e = r.word(&a.token, &keccak256(&[be(i), map].concat()))?;
            // `blob(160) ‖ uOff(16) ‖ vOff(16) ‖ block(64)`: a credit (`vOff ≠ 0`) reads its blob; a TRIVIAL entry has none
            if e[22..24] != [0, 0] {
                ptrs.push(low_addr(&e, 12));
            }
            pending.push(json!({"index": i, "word": hx(&e)}));
        }
        request["account"] = json!(account.iter().map(|w| hx(w)).collect::<Vec<_>>());
        request["pending"] = json!(pending);
        request["accWords"] = json!(acc_words);
        request["sendCounterWord"] = json!(hx(&r.word(&a.token, &counter_slot(&root, &a.ua)?)?));
        request["keyVersion"] = json!(v);
        request["keyVersions"] = json!(hx(&r.word(&a.registry, &versions_slot(&a.ua))?));
        request["forOp7"] = json!(a.for_op7 == Some(true));
        r.blobs(&ptrs)?
    } else {
        let (from, counter, leg) = (a.from_ua.ok_or("--from-ua")?, a.send_counter.ok_or("--send-counter")?, a.leg.ok_or("--leg")?);
        // `PqzCore.entryRefOf`, then `entryPtr[entryRef]`
        let tag = keccak256(b"SCAAS-PQZ-ENTRY-V1");
        let entry_ref = keccak256(&[tag, be(a.chain_id), a.chain_uid, addr_word(&a.token), from, be(counter)].concat());
        let entry_ptr = r.word(&a.token, &keccak256(&[entry_ref, add(&root, at("entryPtr[V]")?.0)].concat()))?;
        if entry_ptr == [0; 32] {
            return Err("no entry of --from-ua at --send-counter on this token".into());
        }
        let (mode, auditor_ua) = (tok("auditorMode")?, tok("auditorUA")?);
        if auditor_ua != a.ua || !matches!(field(&mode, "auditorMode")?, 1 | 2) {
            return Err("R6: --ua is not the token's auditor, or the token has no auditor".into());
        }
        request["chainId"] = json!(a.chain_id);
        request["entryRef"] = json!(hx(&entry_ref));
        request["fromUA"] = json!(hx(&from));
        request["sendCounter"] = json!(counter);
        request["entryPtr"] = json!(hx(&entry_ptr));
        request["leg"] = json!(leg);
        request["auditorMode"] = json!(hx(&mode));
        request["auditorUA"] = json!(hx(&auditor_ua));
        r.blobs(&[low_addr(&entry_ptr, 0), key_ptr])?
    };
    let key_code = blobs.iter().find(|b| b["address"] == json!(hx(&key_ptr))).and_then(|b| b["code"].as_str()).map(unhex).transpose()?;
    request["blobs"] = json!(blobs);
    // R3: the block still the one read (no reorg, a consistent node), before anything else happens
    let again = rpc(url, "eth_getBlockByNumber", json!([format!("0x{block:x}"), false]))?;
    if again["hash"].as_str() != Some(r.hash.as_str()) {
        return Err("R3: the block changed during the read (a reorg or an inconsistent node)".into());
    }
    Ok(Words { request, block, hash: r.hash, key_code: key_code.unwrap_or_default() })
}

/// The wallet and the key's `account`, `index` of the stdin JSON `{mnemonic, passphrase?, account, index}`.
fn key(v: &Value) -> Result<(scaas_ua::wallet::Wallet, u32, u32), String> {
    let o = v.as_object().ok_or("stdin: a JSON object")?;
    if !o.keys().all(|k| ["mnemonic", "passphrase", "account", "index"].contains(&k.as_str())) {
        return Err("stdin: only mnemonic, passphrase, account, index".into());
    }
    let n = |k: &str| o.get(k).and_then(Value::as_u64).and_then(|x| u32::try_from(x).ok()).ok_or(format!("stdin: {k}"));
    let w = scaas_ua::wallet::Wallet::from_mnemonic(
        o.get("mnemonic").and_then(Value::as_str).ok_or("stdin: mnemonic")?,
        o.get("passphrase").map_or(Some(""), Value::as_str).ok_or("stdin: passphrase")?,
    )
    .map_err(|e| format!("the wallet: {e:?}"))?;
    Ok((w, n("account")?, n("index")?))
}

/// `decoys` (module doc): the candidates up to the sync point, the optional activity filter, `pickDecoys`, the chosen keys.
fn decoys(a: &Args) -> Result<Value, String> {
    let url = a.rpc.as_str();
    let (r, block) = open(a)?;
    // another block of the same chain, by hash, the node's answer checked (R3); re-checked after the last read
    let mut pins = vec![(block, r.hash.clone())];
    let mut pin = |n: u64| -> Result<Reader<'_>, String> {
        let b = rpc(url, "eth_getBlockByNumber", json!([format!("0x{n:x}"), false]))?;
        if qty(&b["number"])? != n {
            return Err("R3: the node answered another block than the one asked for".into());
        }
        let hash = b["hash"].as_str().ok_or("R3: no block hash")?.to_string();
        pins.push((n, hash.clone()));
        Ok(Reader { url, hash })
    };
    let sync = a.sync_block.unwrap_or(block);
    if sync > block {
        return Err("--sync-block is past the read block".into());
    }
    let n = pin(sync)?.word(&a.registry, &keccak256(&[be(PQZ_LIST), be(REG_COUNT_SLOT)].concat()))?;
    let n = (n[..24] == [0; 24]).then(|| u64::from_be_bytes(n[24..].try_into().unwrap_or_default())).filter(|n| *n <= MAX_LIST)
        .ok_or("the registry's list is longer than this tool reads")?;
    let list = keccak256(&[be(PQZ_LIST), be(REG_AT_SLOT)].concat());
    let mut exclude = a.exclude.clone();
    exclude.push(a.ua);
    exclude.extend(a.recipient);
    // each candidate's `(latest, current)`; a UA whose latest version of this set's length is not yet current is pending (KV-7)
    let mut candidates: Vec<Word> = Vec::new();
    let mut current = std::collections::BTreeMap::new();
    for i in 0..n {
        let u = r.word(&a.registry, &keccak256(&[be(i), list].concat()))?;
        if candidates.contains(&u) || exclude.contains(&u) {
            continue;
        }
        let vw = r.word(&a.registry, &versions_slot(&u))?;
        let (latest, cur) = (u64::from_be_bytes(vw[24..].try_into().unwrap_or_default()), u64::from_be_bytes(vw[16..24].try_into().unwrap_or_default()));
        if latest > cur {
            let rec = r.word(&a.registry, &pqz_key_slot(&u, latest))?;
            if r.code(&low_addr(&rec, 0))?.len() == 1 + PK_BYTES {
                continue;
            }
        }
        current.insert(u, cur);
        candidates.push(u);
    }
    let mut request = json!({"exclude": exclude.iter().map(|u| hx(u)).collect::<Vec<_>>(), "count": a.count});
    if let Some(u) = a.recipient {
        request["recipient"] = json!(hx(&u));
    }
    if let Some(w) = a.window {
        let old = block.checked_sub(w).filter(|_| w >= 2).ok_or("--window: at least 2 and at most the read block")?;
        let (old, mid) = (pin(old)?, pin(block - w / 2)?);
        let root = erc7201("scaas.pqz");
        let s0 = at("acct[U][7].pendingCount")?.1;
        // the counters an account's activity moves: `pendingCount`, `rolled` (the current version's word 0) and the UA's
        // `sendCounter`; `holder`: the last
        let moved = |x: &Reader, y: &Reader, base: &Word, ctr: &Word| -> Result<bool, String> {
            let (x2, y2) = (x.word(&a.token, ctr)?, y.word(&a.token, ctr)?);
            let debit = field(&x2, "sendCounter[U]")? != field(&y2, "sendCounter[U]")?;
            if a.filter.as_deref() == Some("holder") || debit {
                return Ok(debit);
            }
            let (x0, y0) = (x.word(&a.token, &add(base, s0))?, y.word(&a.token, &add(base, s0))?);
            Ok(field(&x0, "acct[U][7].pendingCount")? != field(&y0, "acct[U][7].pendingCount")?
                || field(&x0, "acct[U][7].rolled")? != field(&y0, "acct[U][7].rolled")?)
        };
        let (mut kept, mut weights) = (Vec::new(), Vec::new());
        for u in candidates {
            // ponytail: the current version of the read block; a rotation inside the window reads the new account's counters
            let (base, ctr) = (acct_base(&root, &u, current[&u])?, counter_slot(&root, &u)?);
            let w = if moved(&mid, &r, &base, &ctr)? { 2 } else if moved(&old, &mid, &base, &ctr)? { 1 } else { 0 };
            if w > 0 {
                kept.push(u);
                weights.push(w);
            }
        }
        candidates = kept;
        request["weights"] = json!(weights);
    }
    request["candidates"] = json!(candidates.iter().map(|u| hx(u)).collect::<Vec<_>>());
    let out = if a.words {
        json!({"command": "decoys", "request": request})
    } else {
        let picked: Value = serde_json::from_str(
            &scaas_ua::facade::decoys::pick_json(request.to_string().as_bytes()).map_err(|e| format!("pickDecoys: {e:?}"))?,
        )
        .map_err(|_| "pickDecoys: not JSON")?;
        let mut legs = Vec::new();
        for u in picked["decoys"].as_array().ok_or("pickDecoys: no decoys")? {
            let ua: Word = fixed("decoy", u.as_str().ok_or("pickDecoys: a UA")?)?;
            // `pqzKey[ua][current]`: `ptr(160) ‖ proven(8) ‖ added(8)`; the code `0x00 ‖ pk`
            let rec = r.word(&a.registry, &pqz_key_slot(&ua, current.get(&ua).copied().ok_or("pickDecoys: not a candidate")?))?;
            let code = r.code(&low_addr(&rec, 0))?;
            match code.split_first() {
                Some((0, pk)) if rec[11] == 1 && pk.len() == PK_BYTES => legs.push(json!({"ua": hx(&ua), "pk": hx(pk)})),
                _ => return Err(format!("the PQZ key of listed UA {} is not a proven key of this set", hx(&ua))),
            }
        }
        let mut out = json!({"decoys": legs});
        if a.recipient.is_some() {
            out["legs"] = picked["legs"].clone();
        }
        out
    };
    for (n, h) in &pins {
        recheck(url, *n, h)?;
    }
    let mut out = out;
    for (k, v) in [("syncBlock", json!(sync)), ("listCount", json!(n)), ("block", json!(block)), ("blockHash", json!(r.hash))] {
        out[k] = v;
    }
    Ok(out)
}

fn run(a: &Args) -> Result<Value, String> {
    if a.command == "decoys" {
        return decoys(a);
    }
    if a.words {
        let r = read(a)?;
        return Ok(json!({"command": a.command, "request": r.request, "block": r.block, "blockHash": r.hash}));
    }
    if std::io::stdin().is_terminal() {
        return Err("pipe the key JSON on stdin (pqz-read … < key.json); a terminal would echo it".into());
    }
    let mut input = Zeroizing::new(String::new());
    std::io::stdin().read_to_string(&mut input).map_err(|e| e.to_string())?;
    let mut kv: Value = serde_json::from_str(&input).map_err(|_| "stdin: key JSON expected".to_string())?;
    let handle = key(&kv);
    wipe(&mut kv);
    let (wallet, account, index) = handle?;
    let k = wallet.pqz_key_version(account, index, a.key_version.ok_or("--key-version")?).map_err(|e| format!("the key: {e:?}"))?;
    let r = read(a)?;
    // R6: the registry's key of --ua is this handle's (SSTORE2: `0x00 ‖ pk`); ua-rs checks it again, with `proven`
    if r.key_code.split_first() != Some((&0, k.pk().as_slice())) {
        return Err("R6: the registry's PQZ key of --ua is not this key".into());
    }
    // R7: no request after this line
    let out = k.call(&a.command, r.request.to_string().as_bytes()).map_err(|e| format!("ua-rs refused the words: {e:?}"))?;
    let mut v: Value = serde_json::from_str(&out).map_err(|_| "ua-rs: not JSON")?;
    v["block"] = json!(r.block);
    v["blockHash"] = json!(r.hash);
    Ok(v)
}

/// Overwrite every string in the parsed key JSON.
// ponytail: best effort, as zether-read-balance: serde's buffers and the mnemonic's copies inside bip39 are not reachable here.
fn wipe(v: &mut Value) {
    match v {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(wipe),
        Value::Object(o) => o.values_mut().for_each(wipe),
        _ => {}
    }
}

fn main() -> ExitCode {
    match parse().and_then(|a| run(&a)) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        let c = curl_config("https://node/x?key=a\"b", r#"{"a":"\\"}"#);
        assert!(c.contains(r#"url = "https://node/x?key=a\"b""#), "{c}");
        assert!(!curl_config("-o /tmp/x", "{}\nurl = \"evil\"").contains("\nurl = \"evil"), "no injected lines");
        assert_eq!(add(&[0xff; 32], 1), [0; 32]);
        assert_eq!(hx(&erc7201("scaas.pqz")), "0xda865ec17214f25b93cdb133d719c79392c290a4b9089fd0bba156256c521500");
        assert_eq!(unhex("0x0aFf").unwrap(), [10, 255]);
        assert!(unhex("0x0").is_err() && unhex("zz").is_err());
        let mut v: Value = serde_json::from_str(r#"{"mnemonic":"abc","n":["ab"]}"#).unwrap();
        wipe(&mut v);
        assert_eq!(v, json!({"mnemonic": "", "n": [""]}));
    }

    /// The slot the registry's layout pin gives `field`: its probe writes one field per slot, `s.<field>…; // <slot>`.
    fn pin_slot(pin: &str, field: &str) -> Option<u64> {
        pin.lines().find_map(|l| {
            let rest = l.trim().strip_prefix("s.")?.strip_prefix(field)?;
            rest.starts_with(['[', '.', ' ']).then_some(())?;
            rest.rsplit_once("// ")?.1.split_whitespace().next()?.parse().ok()
        })
    }

    /// T20b: the registry slots this reader uses are the layout pin's (`UAStore.Layout`, ua-mtx-merge's
    /// `test/ua/UAStoreLayout.t.sol`), and the pin's assertions fix the packing of the two words decoded (`pqzKey[ua][v]`
    /// `ptr ‖ proven ‖ added`, `pqzVersions[ua]` `latest ‖ current ‖ listed`).
    #[test]
    fn registry_slots_are_the_layout_pin() {
        let pin = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../smartcontracts/evm/test/ua/UAStoreLayout.t.sol"))
            .unwrap();
        for (field, slot) in [("pqzKey", REG_PQZ_KEY_SLOT), ("pqzVersions", REG_PQZ_VERSIONS_SLOT), ("uaCount", REG_COUNT_SLOT),
            ("uaAt", REG_AT_SLOT)]
        {
            assert_eq!(pin_slot(&pin, field), Some(slot), "{field}");
        }
        assert_eq!(pin_slot(&pin, "pqzKeyUsed"), Some(18), "a longer name is another field");
        assert!(pin.contains(r#"uint256(0x73) | 1 << 160 | 1 << 168, "2 pqzKey[ua][version]: ptr, proven, added""#));
        assert!(pin.contains(r#"uint256(0x82) | uint256(0x83) << 64 | 1 << 128, "17 pqzVersions: latest, current, listed""#));
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
        assert!(catalogued(&word(1, PQZ_KINDS[0])), "positive control");
        assert!(PQZ_KINDS.iter().all(|k| catalogued(&word(1, *k))), "every kind of this reader");
        assert!(!catalogued(&word(0, PQZ_KINDS[0])), "class 0: not made here");
        assert!(!catalogued(&word(2, PQZ_KINDS[0])), "class DEX");
        assert!(!catalogued(&word(1, 2)), "the other confidential family");
        let mut wide = word(1, PQZ_KINDS[0]);
        wide[28] = 1; // kind 256 + k: a uint16 kind, not its low byte
        assert!(!catalogued(&wide), "the kind's high byte");
        let mut old = [0u8; 32];
        (old[2], old[11]) = (1, PQZ_KINDS[0]); // `_info`: exists, kind
        assert!(!catalogued(&old), "the old one-word packing");
    }
}
