// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! pqz-read — the PQZ reference reading layer (ARCH-POS-13, "never a decryption oracle"; spec no-decryption-oracle §4.2 R1–R7,
//! §4.3, §4.12; ua-rs-sign T15m, owner 2026-11-07). The PQZ twin of `zether-read-balance --rpc`. Native only. UNAUDITED.
//!
//!   pqz-read --rpc <url> [--rpc <url> … [--rpc-agree]] --chain-id <n> --chain-uid <genesis hash> --factory <address>
//!            --registry <address> --token <address> --ua <bytes32> (--depth <n> | --finalized)
//!            [--command balance] --key-version <v> --for-op7 <true|false>               (the holder's own balance of version v)
//!            --command balanceProven --key-version <v> --for-op7 <true|false>          (the same by the proof path, path (B))
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
//! - **R1** every `--rpc` is a node the holder names here (their own, or one they configured); this tool takes named nodes only,
//!   no default list and no discovery (ARCH-POS-15: a reader that adds them applies its rule). `--rpc` once or more (owner
//!   2026-11-08), each node distinct: by default the nodes are **failover** in the order given, every word of a result from the
//!   first node that answers the whole read (R2 to R6, the R3 re-check included), and after any failure the next node from
//!   scratch, never a mix; with **`--rpc-agree`** every node reads the whole at one block number (the smallest the answering
//!   nodes choose, so a far-future answer moves nothing), and a strict majority of the named nodes (⌊n/2⌋ + 1) must return the
//!   same complete read, compared over the whole read, never word by word; that majority's words are the ones used, and its
//!   nodes are re-checked (R3) after every read. All failing, or no majority: the refusal. The URL and body go to `curl` on
//!   its stdin (`--config -`, `-q` first), never in argv.
//! - **R2** `eth_chainId` and `eth_getBlockByNumber("0x0").hash` must equal `--chain-id` and `--chain-uid` (NET-ALL-22).
//! - **R3** one block: the chain's `finalized` block (`--finalized`) or `head − depth` (`--depth`, NET-EVM-04); every read
//!   names it by hash (EIP-1898, `requireCanonical`); the node must answer the block asked for, and the same number must still
//!   carry the same hash after the last read (else the read is refused: a reorg or an inconsistent node).
//! - **R4** storage only: `eth_getStorageAt` and `eth_getCode` at that block; the one view is R5's release probe, at the same
//!   block from the same node. (`keccak256(code) == codeHash` is not checked: no `eth_getProof`; a residual, as in
//!   `zether-read-balance`.)
//! - **R5** the token is catalogued by `--factory` with a PQZ kind (`OpenFactory._rec[token]`, the factory index's record at
//!   slot 8: `contractClass` TOKEN, `kind` NORMAL_PQZ, WRAPPED_PQZ, NORMAL_PQZ_REGULATED or WRAPPED_PQZ_REGULATED), its slot
//!   and packing held to their pin, ua-mtx-merge's `test/zether/ZetherStateVectors.t.sol` (T20b, T15m2); and its code is a clone
//!   of a chain-neutral release, the EIP-1167 proxy with its `ChainEnv` (owner 2026-11-08; `factory::clone_env`); and it is of
//!   release 3h or later: `proofStore()` (`eth_call` at the read block) answers 0 or 1 (proof-path spec C9). An earlier release
//!   is refused by name, for every command, since `ua-rs` parses 3h's layout only (owner 2026-11-09, no-oracle spec §4.2 R5's
//!   Change, §4.14.1).
//! - **R6** `--registry` is the registry the token's `ChainEnv` names (owner 2026-11-08); `keyRecord` is `--registry`'s `pqzKey[--ua][--key-version]` (`UAStore.Layout` slot 2, per version) and its code
//!   must hold this handle's key; `keyVersions` its `pqzVersions[--ua]` (slot 17: `latest ‖ current ‖ listed`, which `ua-rs`
//!   checks against `--key-version`); for `auditRead` `--ua` must be the token's `auditorUA` and its `auditorMode` not NONE
//!   (`ua-rs` checks the entry's copy; a copy made under another auditor version is found by trying each).
//! - **R7** every read on every node, the R3 re-checks included, happens before the key is used; nothing after it goes back to
//!   any node (a failover never follows a key use).
//!
//! The token's slots come from `ua-rs`'s [`STATE_LAYOUT`] (T19c's pin of `scaas.pqz`, compared with the pin by the facade's
//! tests) under the ERC-7201 root of `scaas.pqz`; the words read are exactly those [`STATE_LAYOUT`] lists for the command.
//! Prints `ua-rs`'s answer with `block` and `blockHash` (`--words`: `{command, request, block, blockHash}`).
//!
//! **`balanceProven`** (no-oracle spec §4.14.11; ua-rs-sign T20d8): path (B)'s words (`provenOpen`: the account, `lastRecord` =
//! `debitRec[--ua][lastDebit − 1]` at slot 19, the window `[p_last, p)`, the key's and `accBlob`'s codes, `auditorUA`), and for
//! each credit of the window its history and its sender's state: the debit `(fromUA, k)` from the one `PqzDebitProof` log of the
//! slot's blob (LOG: its `blob` topic; its data decoded here into `header` and P, Fable P3-1) or from the `Credited` log of
//! `(--ua, index)` and its transaction (NONE: a direct or relayed call of a PQZ transfer entry to the token, decoded by its ABI,
//! the relayed one's envelope binding recomputed; `k` the sender counter whose `entryRef` the log names; a call through another
//! contract is refused by name, it needs a trace); its record, the sender's window and the keys by the tail's `kv`, every code
//! once. History (`eth_getLogs`, `eth_getTransactionByHash`) comes from the same named nodes at the read block (R4's one
//! extension: a viewing's words may come from any source, §4.14.6). Then `provenOpen`, one `provenAdd`, `balanceProven`: a credit
//! refused is reported (take path (A) under R1–R6, or stop).
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
use scaas_ua::facade::pqz_pack::{ACC_WORDS, PKP, VP};
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
    rpc: Vec<String>,
    agree: bool,
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
        if !seen.insert(f.clone()) && f != "--rpc" {
            return Err(format!("{f} given twice"));
        }
        let mut val = || it.next().ok_or(format!("{f} needs a value"));
        let int = |v: String| v.parse::<u64>().map_err(|_| format!("{f}: integer"));
        match f.as_str() {
            "--rpc" => {
                let u = val()?;
                if a.rpc.contains(&u) {
                    return Err("--rpc: the same node twice".into());
                }
                a.rpc.push(u);
            }
            "--rpc-agree" => a.agree = true,
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
        "balanceProven" if a.for_op7.is_some() && a.key_version.is_some() && entry == 0 => {}
        "balanceProven" => return Err("balanceProven needs --key-version <v>, --for-op7 <true|false> and no entry fields".into()),
        "auditRead" if a.for_op7.is_none() && a.key_version.is_some() && entry == 3 => {}
        "auditRead" => return Err("auditRead needs --key-version, --from-ua, --send-counter and --leg (no --for-op7)".into()),
        c => return Err(format!("--command {c}: balance or auditRead, balanceProven, or decoys")),
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

/// One JSON-RPC call to one named node (R1), through `curl`.
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

/// The words of one block (R3), by hash (EIP-1898), storage and code only (R4), from one named node (R1).
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
    /// R5 (owner 2026-11-09): the token answers `proofStore()` with 0 (NONE) or 1 (LOG) at this block, so it is of release 3h or
    /// later (proof-path spec C9); a revert, an empty or any other answer is a release before 3h.
    fn release_3h(&self, token: &[u8; 20]) -> Result<(), String> {
        let call = json!({"to": hx(token), "data": hx(&keccak256(b"proofStore()")[..4])});
        let answer = rpc(self.url, "eth_call", json!([call, self.at()])).ok().and_then(|v| v.as_str().map(unhex));
        match answer {
            Some(Ok(w)) if w.len() == 32 && w[..31] == [0; 31] && w[31] <= 1 => Ok(()),
            _ => Err("R5: the token is of a release before 3h (proofStore() does not answer); ua-rs reads release 3h only".into()),
        }
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
#[derive(PartialEq)]
struct Words {
    request: Value,
    /// `balanceProven`: `provenAdd`'s `{blobs, credits}` (else null).
    adds: Value,
    block: u64,
    hash: String,
    key_code: Vec<u8>,
}

/// R2 on node `url`: the configured chain.
fn configured(a: &Args, url: &str) -> Result<(), String> {
    if qty(&rpc(url, "eth_chainId", json!([]))?)? != a.chain_id {
        return Err("R2: eth_chainId is not the configured chain".into());
    }
    let genesis = rpc(url, "eth_getBlockByNumber", json!(["0x0", false]))?;
    if unhex(genesis["hash"].as_str().ok_or("R2: no genesis hash")?)? != a.chain_uid {
        return Err("R2: the genesis hash is not the configured chain_uid".into());
    }
    Ok(())
}

/// R2, then R3's number on node `url`: `head − depth`, or the `finalized` block's.
fn chosen(a: &Args, url: &str) -> Result<u64, String> {
    configured(a, url)?;
    match a.depth {
        Some(d) => qty(&rpc(url, "eth_blockNumber", json!([]))?)?.checked_sub(d).ok_or("R3: the chain is shorter than the confirmation depth".into()),
        None => qty(&rpc(url, "eth_getBlockByNumber", json!(["finalized", false]))?["number"]),
    }
}

/// R2, R3 and R5 on node `url`: the configured chain, its read block (by hash; `block_at`, the number `--rpc-agree` fixed, or this
/// node's own `finalized` / `head − depth`), the token catalogued with a PQZ kind.
fn open<'u>(a: &Args, url: &'u str, block_at: Option<u64>) -> Result<(Reader<'u>, u64), String> {
    configured(a, url)?;
    // R3
    let (tag, want) = match (block_at, a.depth) {
        (Some(n), _) => (format!("0x{n:x}"), Some(n)),
        (None, Some(d)) => {
            let n = qty(&rpc(url, "eth_blockNumber", json!([]))?)?.checked_sub(d).ok_or("R3: the chain is shorter than the confirmation depth")?;
            (format!("0x{n:x}"), Some(n))
        }
        (None, None) => ("finalized".to_string(), None),
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
    // R5, R6 (owner 2026-11-08): the token's code is a clone of a chain-neutral release, and `--registry` is the one its
    // `ChainEnv` names
    let Some((_, env)) = scaas_ua::factory::clone_env(&r.code(&a.token)?) else {
        return Err("R5: the token is not a clone of a chain-neutral release".into());
    };
    if env.registry != a.registry {
        return Err("R6: --registry is not the token's registry".into());
    }
    r.release_3h(&a.token)?;
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

/// R1, the default (owner 2026-11-08): failover over the named nodes in the order given. `read` runs whole on one node; after
/// any failure the next node starts from scratch, so a result's words are always one node's; all failing is the refusal (one
/// node: its own error, as before).
fn failover<T>(a: &Args, read: impl Fn(&str) -> Result<T, String>) -> Result<T, String> {
    let mut last = String::new();
    for url in &a.rpc {
        match read(url) {
            Ok(t) => return Ok(t),
            Err(e) => last = e,
        }
    }
    Err(if a.rpc.len() == 1 { last } else { format!("R1: no --rpc answered the whole read (the last: {last})") })
}

/// `--rpc-agree` with two or more nodes.
fn agreeing(a: &Args) -> bool {
    a.agree && a.rpc.len() > 1
}

/// `--rpc-agree`: a strict majority of the named nodes.
fn majority(a: &Args) -> usize {
    a.rpc.len() / 2 + 1
}

/// `--rpc-agree`: the block number every node reads, the smallest the answering nodes choose (R2 on each).
fn agreed_block(a: &Args) -> Result<u64, String> {
    a.rpc.iter().filter_map(|u| chosen(a, u).ok()).min().ok_or_else(|| "R1: no --rpc answered".into())
}

/// `--rpc-agree`: `read` runs whole on every node of `urls`; the result is the one at least `need` of them returned identically,
/// compared over the whole read (never word by word), with the nodes that returned it; a node that fails is outvoted.
fn agree<'u, T: PartialEq>(urls: &[&'u str], need: usize, read: impl Fn(&str) -> Result<T, String>) -> Result<(T, Vec<&'u str>), String> {
    let mut got: Vec<(&'u str, T)> = urls.iter().filter_map(|u| read(u).ok().map(|t| (*u, t))).collect();
    let count = |t: &T| got.iter().filter(|g| g.1 == *t).count();
    let best = (0..got.len()).max_by_key(|i| got.get(*i).map_or(0, |g| count(&g.1))).ok_or("R1: no --rpc answered the read")?;
    let members: Vec<&'u str> = got.iter().filter(|g| Some(&g.1) == got.get(best).map(|b| &b.1)).map(|g| g.0).collect();
    if members.len() < need {
        return Err("R1: no strict majority of the --rpc nodes returned the same read".into());
    }
    Ok((got.swap_remove(best).1, members))
}

/// `--rpc-agree`, R3 after every node's read: at least `need` of the majority's nodes still carry every pinned block's hash.
fn rechecked(members: &[&str], pins: &[(u64, String)], need: usize) -> Result<(), String> {
    if members.iter().filter(|u| pins.iter().all(|(n, h)| recheck(u, *n, h).is_ok())).count() < need {
        return Err("R1: no strict majority of the --rpc nodes kept the read block (R3)".into());
    }
    Ok(())
}

/// The request's words under R1–R6 (`pk`: the handle's key, R6's check, when a key is used), from the named nodes.
fn read_words(a: &Args, pk: Option<&[u8]>) -> Result<Words, String> {
    if !agreeing(a) {
        return failover(a, |url| read(a, url, None, pk));
    }
    let n = agreed_block(a)?;
    let urls: Vec<&str> = a.rpc.iter().map(String::as_str).collect();
    let (w, members) = agree(&urls, majority(a), |url| read(a, url, Some(n), pk))?;
    rechecked(&members, &[(w.block, w.hash.clone())], majority(a))?;
    Ok(w)
}

/// The words on node `url` at its own block (`block_at`: the agreed number), the R6 key check when `pk` is given, the R3 re-check.
fn read(a: &Args, url: &str, block_at: Option<u64>, pk: Option<&[u8]>) -> Result<Words, String> {
    let (r, block) = open(a, url, block_at)?;
    // R4, R6: the token's words by the pinned layout, the registry's key record of --ua
    let root = erc7201("scaas.pqz");
    let tok = |label: &str| -> Result<Word, String> { r.word(&a.token, &add(&root, at(label)?.0)) };
    let psid = tok("psid")?;
    let v = a.key_version.ok_or("--key-version")?;
    let key_record = r.word(&a.registry, &pqz_key_slot(&a.ua, v))?;
    let key_ptr = low_addr(&key_record, 0);
    let mut request = json!({"chainUid": hx(&a.chain_uid), "token": hx(&a.token), "block": block, "psid": hx(&psid),
        "keyRecord": hx(&key_record), "ua": hx(&a.ua)});
    let mut adds = Value::Null;
    let blobs = if a.command == "balance" || a.command == "balanceProven" {
        // path (B) (`balanceProven`, T20d8): the window starts at the last own debit's `p`, `accBlob` read with that debit
        let proven = a.command == "balanceProven";
        let base = acct_base(&root, &a.ua, v)?;
        // the 4 slots of `acct[ua][v]` (3h: `lastDebit` in slot 2; `accHash` 3, the pending map 4, `accWords` from 5)
        let account = (0..4).map(|i| r.word(&a.token, &add(&base, i))).collect::<Result<Vec<_>, _>>()?;
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
        } else if acc_blob != [0; 20] && !proven {
            ptrs.push(acc_blob);
        }
        let from = if proven { last_record(a, &r, &root, &account, acc_blob, &mut ptrs, &mut request)? } else { rolled };
        // the facade's `p` (CTR-PQZ-06): the pending window `[rolled, p)` (path (B): `[p_last, p)`) is read by index only
        let room = (K_MAX as u64).checked_sub(units + 1).ok_or("the account's accUnits are past K_MAX")?;
        let inline = if a.for_op7 == Some(true) && psid == PQZH_ID { INLINE_MAX_PQZH } else { INLINE_MAX };
        let p = count.min(rolled.saturating_add(inline.min(room)));
        if from > p {
            return Err("the account's last record is past its window".into());
        }
        let map = add(&base, at("acct[U][7].pending[3]")?.1);
        let mut pending = Vec::new();
        let mut proof_path = if proven { Some(ProofPath::of(&r, &tok)?) } else { None };
        for i in from..p {
            let e = r.word(&a.token, &keccak256(&[be(i), map].concat()))?;
            // `blob(160) ‖ uOff(16) ‖ vOff(16) ‖ block(64)`: a credit (`vOff ≠ 0`) reads its blob (path (B): its history); a
            // TRIVIAL entry has none
            if e[22..24] != [0, 0] && !proven {
                ptrs.push(low_addr(&e, 12));
            } else if let (true, Some(pp)) = (e[22..24] != [0, 0], proof_path.as_mut()) {
                let (c, x) = credit(a, url, block, &root, &mut pp.codes, i, &e, &pp.auditor, pp.fee, pp.compact)?;
                pp.credits.push(c);
                pp.ptrs.extend(x);
            }
            pending.push(json!({"index": i, "word": hx(&e)}));
        }
        if let Some(pp) = proof_path {
            adds = json!({"blobs": pp.codes.json(&pp.ptrs), "credits": pp.credits});
            request["auditorUA"] = json!(hx(&pp.auditor));
            request["chainId"] = json!(a.chain_id);
            request["registry"] = json!(hx(&a.registry));
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
        let entry_ref = entry_ref_of(a, &from, counter);
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
    let key_code = key_code.unwrap_or_default();
    // R6: the registry's key of --ua is this handle's (SSTORE2: `0x00 ‖ pk`); ua-rs checks it again, with `proven`
    if pk.is_some_and(|pk| key_code.split_first() != Some((&0, pk))) {
        return Err("R6: the registry's PQZ key of --ua is not this key".into());
    }
    Ok(Words { request, adds, block, hash: r.hash, key_code })
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

/// `decoys`' read before the pick on one node: `pickDecoys`'s request (candidates up to the sync point, exclusions, the
/// optional filter's weights), each candidate's current version and the blocks read, each by hash.
#[derive(PartialEq)]
struct DecoyRead {
    request: Value,
    current: std::collections::BTreeMap<Word, u64>,
    sync: u64,
    count: u64,
    block: u64,
    hash: String,
    pins: Vec<(u64, String)>,
}

/// The candidates on node `url` (`block_at`: the agreed number).
fn decoy_read(a: &Args, url: &str, block_at: Option<u64>) -> Result<DecoyRead, String> {
    let (r, block) = open(a, url, block_at)?;
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
    let hash = r.hash.clone();
    Ok(DecoyRead { request, current, sync, count: n, block, hash, pins })
}

/// `pickDecoys` (`facade::decoys`, the OS CSPRNG) over the candidates: once per result, never per node.
fn pick(d: &DecoyRead) -> Result<Value, String> {
    serde_json::from_str(&scaas_ua::facade::decoys::pick_json(d.request.to_string().as_bytes()).map_err(|e| format!("pickDecoys: {e:?}"))?)
        .map_err(|_| "pickDecoys: not JSON".into())
}

/// The chosen decoys' keys on node `url`, at the read block of `d`.
fn decoy_legs(a: &Args, url: &str, d: &DecoyRead, picked: &Value) -> Result<Value, String> {
    let r = Reader { url, hash: d.hash.clone() };
    let mut legs = Vec::new();
    for u in picked["decoys"].as_array().ok_or("pickDecoys: no decoys")? {
        let ua: Word = fixed("decoy", u.as_str().ok_or("pickDecoys: a UA")?)?;
        // `pqzKey[ua][current]`: `ptr(160) ‖ proven(8) ‖ added(8)`; the code `0x00 ‖ pk`
        let rec = r.word(&a.registry, &pqz_key_slot(&ua, d.current.get(&ua).copied().ok_or("pickDecoys: not a candidate")?))?;
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
    Ok(out)
}

/// `decoys` (module doc) over the named nodes (R1): failover runs the whole (candidates, pick, keys, R3 re-checks) on one node,
/// from scratch on the next after a failure; `--rpc-agree` takes the candidates a strict majority returned identically, picks
/// once, and the keys that majority's nodes return identically (each node counted over its whole read), then re-checks them.
fn decoys(a: &Args) -> Result<Value, String> {
    let words = |d: &DecoyRead| json!({"command": "decoys", "request": d.request});
    let (d, mut out) = if !agreeing(a) {
        failover(a, |url| {
            let d = decoy_read(a, url, None)?;
            let out = if a.words { words(&d) } else { decoy_legs(a, url, &d, &pick(&d)?)? };
            for (n, h) in &d.pins {
                recheck(url, *n, h)?;
            }
            Ok((d, out))
        })?
    } else {
        let n = agreed_block(a)?;
        let urls: Vec<&str> = a.rpc.iter().map(String::as_str).collect();
        let (d, members) = agree(&urls, majority(a), |url| decoy_read(a, url, Some(n)))?;
        let (out, members) = if a.words {
            (words(&d), members)
        } else {
            let picked = pick(&d)?;
            agree(&members, majority(a), |url| decoy_legs(a, url, &d, &picked))?
        };
        rechecked(&members, &d.pins, majority(a))?;
        (d, out)
    };
    for (k, v) in [("syncBlock", json!(d.sync)), ("listCount", json!(d.count)), ("block", json!(d.block)), ("blockHash", json!(d.hash))] {
        out[k] = v;
    }
    Ok(out)
}


// ------------------------------------------------------------------------------------------------------------------------------
// `--command balanceProven` (no-oracle spec §4.14.11; ua-rs-sign T20d8): path (B)'s words and each credit's history
// ------------------------------------------------------------------------------------------------------------------------------

/// `IPqzToken`'s events a credit is found by: `PqzDebitProof` (LOG: its topics name the debit by its op blob, its data the
/// verified header and P) and `Credited` (NONE: the holder's pending index, its data `keyVersion` and `entryRef`).
const EV_PROOF: &str = "PqzDebitProof(address,bytes32,uint64,bytes,bytes)";
const EV_CREDITED: &str = "Credited(bytes32,uint64,uint64,bytes32)";
/// The ABI types of the PQZ transfer entries (`IPqzToken`, `PqzLayer`; `typed_ops.json`'s signatures, group 3h).
const PA: &str = "(uint64,uint256,uint256,bytes32,uint64,bytes32,bytes32,bytes16,bytes32,bytes,bytes,bytes,bytes,bytes)";
const MA: &str = "(uint64,uint256,uint256,bytes32,uint64,bytes32,uint256,bytes16,bytes32,bytes[],(bytes32,bytes,bytes)[],bytes,bytes)";
const UA_ENV: &str = "(bytes32,uint256,uint256,uint256,uint32,address,uint256,address)";
const UA_SIG: &str = "(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[])";
const VERDICT: &str = "((address,uint256,bytes32,bytes32,bytes32,uint32,uint64),(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[]))";
/// The longest search of a NONE credit's `sendCounter` by its `entryRef` (one hash per earlier counter of the sender).
const MAX_COUNTER_SEARCH: u64 = 1 << 20;

/// A PQZ transfer entry: op 7 or op 1, `Compact` (HASH on every token), relayed (the `UAEnvelope` first).
#[derive(Clone, Copy)]
struct Entry {
    multi: bool,
    compact: bool,
    relayed: bool,
}

/// The selector of each transfer entry, direct and relayed (a call through any other function is not read here).
fn entries() -> Vec<([u8; 4], Entry)> {
    let mut out = Vec::new();
    for (multi, name, args) in [(false, "mtxConfidentialTransferSingle", PA), (true, "mtxConfidentialTransfer", MA)] {
        for compact in [false, true] {
            let n = if compact { format!("{name}Compact") } else { name.to_string() };
            for relayed in [false, true] {
                let sig = if relayed {
                    format!("{n}({UA_ENV},{args},bytes,{UA_SIG},bytes,{UA_SIG},{VERDICT})")
                } else {
                    format!("{n}({args},bytes,{UA_SIG},bytes,{VERDICT})")
                };
                let h = keccak256(sig.as_bytes());
                out.push(([h[0], h[1], h[2], h[3]], Entry { multi, compact, relayed }));
            }
        }
    }
    out
}

/// ABI: the word at byte `at`.
fn aw(d: &[u8], at: usize) -> Result<Word, String> {
    d.get(at..at + 32).and_then(|w| w.try_into().ok()).ok_or_else(|| "ABI: short".into())
}
/// ABI: a word that must be a `uint64` (an offset, a length, a counter).
fn au(d: &[u8], at: usize) -> Result<u64, String> {
    let w = aw(d, at)?;
    if w[..24] != [0; 24] {
        return Err("ABI: a value past 64 bits".into());
    }
    Ok(u64::from_be_bytes(w[24..].try_into().map_err(|_| "ABI")?))
}
fn ao(d: &[u8], at: usize) -> Result<usize, String> {
    usize::try_from(au(d, at)?).map_err(|_| "ABI: an offset".into())
}
/// ABI: the `bytes` whose offset (from `base`) is the word at `base + head`.
fn ab(d: &[u8], base: usize, head: usize) -> Result<Vec<u8>, String> {
    let off = base.checked_add(ao(d, base + head)?).ok_or("ABI: an offset")?;
    let n = ao(d, off)?;
    d.get(off + 32..off.checked_add(32 + n).ok_or("ABI: a length")?).map(<[u8]>::to_vec).ok_or_else(|| "ABI: short bytes".into())
}

/// A NONE credit's debit as its call carries it: `fromUA`, the call fields of §4.14.4 step 4 (`fee` without the token's part)
/// and P.
struct Called {
    from: Word,
    multi: bool,
    beneficiary: Word,
    valid_until: u64,
    hash: bool,
    sealed_memo: Vec<u8>,
    binding: Word,
    decoy_fee: u64,
    m: u64,
    proof: Vec<u8>,
}

/// A transfer entry's calldata (`input`, the transaction's): direct (`binding` 0) or relayed (the `UAEnvelope`'s binding,
/// `PqzLayer._uaEnvelopeBinding`: tag `SCAAS-PQZ-UA-ENVELOPE-V1`, `chainId`, `chainUid`, the token, every envelope field but
/// `data`, `relayer` and `feeRecipient` zero unless the mode restricts them). `compact_token`: the token's `disclosureMode` is
/// COMPACT (its default entries commit-reveal).
fn called(a: &Args, input: &[u8], compact_token: bool) -> Result<Called, String> {
    let sel: [u8; 4] = input.get(..4).and_then(|s| s.try_into().ok()).ok_or("NONE: no selector")?;
    let e = entries().into_iter().find(|x| x.0 == sel).ok_or("NONE: the debit's call is not a PQZ transfer entry of this token")?.1;
    let d = input.get(4..).ok_or("ABI")?;
    let (t_head, proof_head, binding) = if e.relayed {
        let env: Vec<Word> = (0..8).map(|i| aw(d, 32 * i)).collect::<Result<_, _>>()?;
        let mode = au(d, 32 * 4)?;
        let keep = |bit: u64, w: &Word| if mode & bit != 0 { *w } else { [0; 32] };
        let token = addr_word(&a.token);
        let b = keccak256(
            &[keccak256(b"SCAAS-PQZ-UA-ENVELOPE-V1"), be(a.chain_id), a.chain_uid, token, env[0], env[1], env[2], env[3], env[4],
                keep(1, &env[5]), env[6], keep(2, &env[7])]
                .concat(),
        );
        (32 * 8, 32 * 9, b)
    } else {
        (0, 32, [0; 32])
    };
    let t = ao(d, t_head)?;
    let proof = ab(d, 0, proof_head)?;
    let w = |i: usize| aw(d, t + 32 * i);
    let valid_until = au(d, t + 32)?;
    let (beneficiary, decoy_fee, memo_at, m) = if e.multi {
        let legs = t.checked_add(ao(d, t + 32 * 10)?).ok_or("ABI: an offset")?;
        (w(5)?, au(d, t + 32 * 6)?, 12, au(d, legs)?)
    } else {
        (w(6)?, 0, 13, 1)
    };
    let sealed_memo = ab(d, t, 32 * memo_at)?;
    Ok(Called { from: w(3)?, multi: e.multi, beneficiary, valid_until, hash: e.compact || compact_token, sealed_memo, binding, decoy_fee, m, proof })
}

/// ABI `(bytes header, bytes proof)`, a `PqzDebitProof`'s data: the 20 header words and P.
fn proof_log(data: &[u8]) -> Result<(Vec<Word>, Vec<u8>), String> {
    let header = ab(data, 0, 0)?;
    if header.len() != 640 {
        return Err("LOG: a header of other than 640 bytes".into());
    }
    Ok((header.chunks_exact(32).map(|c| c.try_into().map_err(|_| "LOG".to_string())).collect::<Result<_, _>>()?, ab(data, 0, 32)?))
}

/// One SSTORE2 code per address and read (a shared op 7 blob fetched once: C-PP-7).
struct Codes<'r, 'u> {
    r: &'r Reader<'u>,
    got: std::collections::BTreeMap<[u8; 20], Vec<u8>>,
}

impl Codes<'_, '_> {
    fn get(&mut self, a: &[u8; 20]) -> Result<&[u8], String> {
        if !self.got.contains_key(a) {
            let c = self.r.code(a)?;
            self.got.insert(*a, c);
        }
        self.got.get(a).map(Vec::as_slice).ok_or_else(|| "code".into())
    }
    fn json(&self, ptrs: &[[u8; 20]]) -> Vec<Value> {
        let mut seen = Vec::new();
        ptrs.iter()
            .filter(|p| if seen.contains(*p) { false } else { seen.push(**p); true })
            .filter_map(|p| self.got.get(p).map(|c| json!({"address": hx(p), "code": hx(c)})))
            .collect()
    }
}

/// `PqzCore.entryRefOf` on the configured chain and token: `keccak256(abi.encode(TAG_ENTRY, chainId, chainUid, token, fromUA, k))`.
fn entry_ref_of(a: &Args, from: &Word, counter: u64) -> Word {
    keccak256(&[keccak256(b"SCAAS-PQZ-ENTRY-V1"), be(a.chain_id), a.chain_uid, addr_word(&a.token), *from, be(counter)].concat())
}

/// `balanceProven`'s state while the window is read: the token's words a credit needs, the codes fetched once, the credits.
struct ProofPath<'r, 'u> {
    auditor: Word,
    fee: u64,
    compact: bool,
    codes: Codes<'r, 'u>,
    credits: Vec<Value>,
    ptrs: Vec<[u8; 20]>,
}

impl<'r, 'u> ProofPath<'r, 'u> {
    /// The token's `auditorUA`, `confidentialFee` (a NONE header's fee; a `uint64` here) and `disclosureMode` (COMPACT: its
    /// default entries commit-reveal).
    fn of(r: &'r Reader<'u>, tok: &dyn Fn(&str) -> Result<Word, String>) -> Result<Self, String> {
        let (auditor, mode, fee) = (tok("auditorUA")?, tok("disclosureMode")?, tok("confidentialFee")?);
        if fee[..24] != [0; 24] {
            return Err("confidentialFee past 64 bits".into());
        }
        Ok(ProofPath {
            auditor,
            fee: u64::from_be_bytes(fee[24..].try_into().map_err(|_| "fee")?),
            compact: field(&mode, "disclosureMode")? == 1,
            codes: Codes { r, got: std::collections::BTreeMap::new() },
            credits: Vec::new(),
            ptrs: Vec::new(),
        })
    }
}

/// `balanceProven`'s start: the last own debit's record `debitRec[--ua][lastDebit − 1]` (slot 19) into `request` as
/// `lastRecord`, `accBlob` (its `v_f`, checked by its tag) among the codes; its `p` (`p_last`; 0 when never debited).
fn last_record(a: &Args, r: &Reader<'_>, root: &Word, account: &[Word], acc_blob: [u8; 20], ptrs: &mut Vec<[u8; 20]>, request: &mut Value)
    -> Result<u64, String> {
    let last = field(account.get(2).ok_or("the account")?, "acct[U][7].lastDebit")?;
    if last == 0 {
        return Ok(0);
    }
    ptrs.push(acc_blob);
    let rb = keccak256(&[be(last - 1), keccak256(&[a.ua, add(root, at("debitRec[U][7].w0")?.0)].concat())].concat());
    let (w0, w1) = (r.word(&a.token, &rb)?, r.word(&a.token, &add(&rb, at("debitRec[U][7].w1")?.1))?);
    request["lastRecord"] = json!({"w0": hx(&w0), "w1": hx(&w1)});
    Ok(scaas_ua::facade::pqz_path::record(&w0, &w1, last - 1).map_err(|_| "the account's last record")?.p)
}

/// The token's words of `balanceProven`'s credits (§4.14.11), read at the block `r` names: for pending index `i` of `--ua`'s
/// window (its slot word `e`), the debit `(fromUA, k)` (LOG: the one `PqzDebitProof` of the slot's blob, by its `blob` topic;
/// NONE: the `Credited` log of `(--ua, i)`, its transaction's call, a direct call or a relayed one to the token, `k` the counter
/// whose `entryRef` the log names), then from state its record, the sender's window, the keys by the tail's `kv` (the holder's own
/// leg left out) and their codes.
#[allow(clippy::too_many_arguments)]
fn credit(a: &Args, url: &str, block: u64, root: &Word, codes: &mut Codes<'_, '_>, i: u64, e: &Word, auditor: &Word, fee: u64, compact: bool)
    -> Result<(Value, Vec<[u8; 20]>), String> {
    let r = codes.r;
    let v = a.key_version.ok_or("--key-version")?;
    let ptr = low_addr(e, 12);
    let to = format!("0x{block:x}");
    let logs = rpc(url, "eth_getLogs", json!([{"address": hx(&a.token), "fromBlock": "0x0", "toBlock": to,
        "topics": [hx(&keccak256(EV_PROOF.as_bytes())), hx(&addr_word(&ptr))]}]))?;
    let logs = logs.as_array().ok_or("eth_getLogs: not a list")?;
    let (from, k, multi, how): (Word, u64, bool, Value) = match logs.as_slice() {
        [l] => {
            let t = l["topics"].as_array().ok_or("LOG: topics")?;
            let word = |j: usize| -> Result<Word, String> { fixed("LOG topic", t.get(j).and_then(Value::as_str).ok_or("LOG: topics")?) };
            let (header, proof) = proof_log(&unhex(l["data"].as_str().ok_or("LOG: data")?)?)?;
            let multi = header.first() == Some(&pqz_ffi::stmt::OP_TAG_TRANSFER_MULTI);
            let k = u64::from_be_bytes(word(3)?[24..].try_into().map_err(|_| "LOG")?);
            (word(2)?, k, multi, json!({"proof": hx(&proof), "header": header.iter().map(|w| hx(w)).collect::<Vec<_>>()}))
        }
        [] => {
            let cl = rpc(url, "eth_getLogs", json!([{"address": hx(&a.token), "fromBlock": "0x0", "toBlock": to,
                "topics": [hx(&keccak256(EV_CREDITED.as_bytes())), hx(&a.ua), hx(&be(i))]}]))?;
            let [l] = cl.as_array().ok_or("eth_getLogs: not a list")?.as_slice() else {
                return Err(format!("NONE: no single Credited log of pending index {i}"));
            };
            let data = unhex(l["data"].as_str().ok_or("NONE: data")?)?;
            let entry_ref = aw(&data, 32)?;
            let tx = rpc(url, "eth_getTransactionByHash", json!([l["transactionHash"]]))?;
            if tx["to"].as_str().map(|t| t.to_ascii_lowercase()) != Some(hx(&a.token)) {
                return Err(format!("NONE: pending index {i} was credited by a call through another contract (it needs a trace; take path (A))"));
            }
            let c = called(a, &unhex(tx["input"].as_str().ok_or("NONE: input")?)?, compact)?;
            let er = |n: u64| entry_ref_of(a, &c.from, n);
            let counter = field(&r.word(&a.token, &counter_slot(root, &c.from)?)?, "sendCounter[U]")?;
            let k = (counter.saturating_sub(MAX_COUNTER_SEARCH)..counter).rev().find(|n| er(*n) == entry_ref)
                .ok_or("NONE: no sendCounter of the call's fromUA gives the Credited entryRef")?;
            let fee = (if c.beneficiary == [0; 32] { 0 } else { fee }).checked_add(c.m.checked_mul(c.decoy_fee).ok_or("fee")?).ok_or("fee")?;
            let mut call = json!({"beneficiaryUA": hx(&c.beneficiary), "fee": fee, "validUntilBlock": c.valid_until,
                "mode": if c.hash { "HASH" } else { "BUNDLE" }, "binding": hx(&c.binding)});
            if c.hash {
                call["sealedMemo"] = json!(hx(&c.sealed_memo));
            }
            (c.from, k, c.multi, json!({"proof": hx(&c.proof), "call": call}))
        }
        _ => return Err(format!("LOG: several PqzDebitProof logs of pending index {i}'s blob")),
    };
    // the record and the sender's window, from state
    let rec_base = keccak256(&[be(k), keccak256(&[from, add(root, at("debitRec[U][7].w0")?.0)].concat())].concat());
    let (w0, w1) = (r.word(&a.token, &rec_base)?, r.word(&a.token, &add(&rec_base, at("debitRec[U][7].w1")?.1))?);
    let rec = scaas_ua::facade::pqz_path::record(&w0, &w1, k).map_err(|_| format!("the record of the debit of pending index {i}"))?;
    let sender = acct_base(root, &from, rec.key_version)?;
    let map = add(&sender, at("acct[U][7].pending[3]")?.1);
    let mut ptrs = vec![ptr];
    if rec.has_prev {
        ptrs.push(rec.prev_blob);
    }
    let mut window = Vec::new();
    for x in rec.p.checked_sub(rec.delta_p).ok_or("the record's Δp")?..rec.p {
        let w = r.word(&a.token, &keccak256(&[be(x), map].concat()))?;
        if w[22..24] != [0, 0] {
            ptrs.push(low_addr(&w, 12));
        }
        window.push(json!({"index": x, "word": hx(&w)}));
    }
    // the keys: the sender's at its version, every other leg's and the auditor's by `kv`
    let d = codes.get(&ptr)?.get(1..).ok_or("an empty op blob")?.to_vec();
    let tail = scaas_ua::facade::pqz_path::tail(&d).map_err(|_| "an op blob's tail")?;
    let (g, m, aud) = scaas_ua::facade::pqz_path::bundle_shape(tail.r_len, PKP, VP).map_err(|_| "an op blob's shape")?;
    let mut keys = vec![(from, rec.key_version)];
    for j in 0..m {
        let end = 16 + PKP * g + (32 + VP * (1 + aud as usize)) * (j + 1);
        let ua: Word = d.get(end - 32..end).and_then(|x| x.try_into().ok()).ok_or("a leg's UA")?;
        let kv = *tail.kv.get(j).ok_or("a leg's kv")?;
        if !(ua == a.ua && kv == v) {
            keys.push((ua, kv));
        }
    }
    if aud {
        keys.push((*auditor, *tail.kv.get(m).ok_or("the auditor's kv")?));
    }
    let mut records = Vec::new();
    for (ua, x) in &keys {
        let w = r.word(&a.registry, &pqz_key_slot(ua, *x))?;
        ptrs.push(low_addr(&w, 0));
        records.push(json!({"ua": hx(ua), "version": x, "word": hx(&w)}));
    }
    for p in &ptrs {
        codes.get(p)?;
    }
    let mut c = json!({"index": i, "fromUA": hx(&from), "sendCounter": k, "form": if multi { "transferMulti" } else { "transfer" },
        "record": {"w0": hx(&w0), "w1": hx(&w1)}, "senderPending": window, "keyRecords": records});
    for (key, val) in how.as_object().ok_or("credit")? {
        c[key] = val.clone();
    }
    Ok((c, ptrs))
}

fn run(a: &Args) -> Result<Value, String> {
    if a.command == "decoys" {
        return decoys(a);
    }
    if a.words {
        let r = read_words(a, None)?;
        let mut out = json!({"command": a.command, "request": r.request, "block": r.block, "blockHash": r.hash});
        if !r.adds.is_null() {
            out["credits"] = r.adds;
        }
        return Ok(out);
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
    let r = read_words(a, Some(k.pk().as_slice()))?;
    // R7: no request after this line
    let call = |cmd: &str, req: &Value| -> Result<Value, String> {
        let out = k.call(cmd, req.to_string().as_bytes()).map_err(|e| format!("ua-rs refused the words: {e:?}"))?;
        serde_json::from_str(&out).map_err(|_| "ua-rs: not JSON".to_string())
    };
    let mut v = if a.command == "balanceProven" {
        let o = call("provenOpen", &r.request)?;
        let mut adds = r.adds.clone();
        adds["session"] = o["session"].clone();
        let got = call("provenAdd", &adds)?;
        if got["refused"] != json!([]) {
            let _ = call("provenCancel", &json!({"session": o["session"]}));
            return Err(format!("ua-rs refused the credits {} (their P did not check): take path (A) under R1–R6, or stop", got["refused"]));
        }
        call("balanceProven", &json!({"session": o["session"]}))?
    } else {
        call(&a.command, &r.request)?
    };
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

    /// T20d8 (Fable P3-1): `PqzDebitProof`'s data decoded here into `header` and P, against the contract's own log
    /// (`state.json` `proofLogs`, both sets): the topics are the event's, the blob's, the UA's and the counter's; a header of
    /// another length is refused.
    #[test]
    fn proof_log_rows_decode() {
        for f in ["state.json", "n2304-kmax4096/state.json"] {
            let p = format!("{}/../../smartcontracts/vectors/pqz/{f}", env!("CARGO_MANIFEST_DIR"));
            let v: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
            let rows = v["proofLogs"].as_array().unwrap();
            assert!(!rows.is_empty());
            for r in rows {
                let (header, proof) = proof_log(&unhex(r["data"].as_str().unwrap()).unwrap()).unwrap();
                assert_eq!(hx(&header.concat()), r["header"].as_str().unwrap(), "{}", r["name"]);
                assert_eq!(hx(&proof), r["proof"].as_str().unwrap());
                let t: Vec<&str> = r["topics"].as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect();
                let blob: [u8; 20] = unhex(r["blob"].as_str().unwrap()).unwrap().try_into().unwrap();
                assert_eq!(t, [hx(&keccak256(EV_PROOF.as_bytes())), hx(&addr_word(&blob)), r["ua"].as_str().unwrap().to_string(),
                    hx(&be(r["sendCounter"].as_u64().unwrap()))]);
            }
            let short = [be(64).to_vec(), be(64 + 32 + 640).to_vec(), be(608).to_vec(), vec![0; 608], be(1).to_vec(), vec![0; 32]].concat();
            assert!(proof_log(&short).is_err(), "a header of 608 bytes");
        }
    }

    /// T20d8: the transfer entries' signatures are the contract's, through the typed rows' (`typed_ops.json`: the four relayed
    /// entries' `abi` and `selector`); the direct ones are the same types without the envelope and `auth`.
    #[test]
    fn transfer_entries_are_the_typed_rows() {
        let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../smartcontracts/vectors/typed/typed_ops.json");
        let v: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
        let sels = entries();
        assert_eq!(sels.len(), 8);
        for (op, multi, compact) in [("UAPqzTransferSingle", false, false), ("UAPqzTransferSingleCompact", false, true),
            ("UAPqzTransfer", true, false), ("UAPqzTransferCompact", true, true)]
        {
            let d = v["ops"][op]["domains"].as_object().unwrap().values().next().unwrap();
            let name = d["abi"].as_str().unwrap().split('(').next().unwrap().to_string();
            let args = if multi { MA } else { PA };
            assert_eq!(d["abi"], json!(format!("{name}({UA_ENV},{args},bytes,{UA_SIG},bytes,{UA_SIG},{VERDICT})")), "{op}");
            let sel = unhex(d["selector"].as_str().unwrap()).unwrap();
            let e = sels.iter().find(|x| x.0[..] == sel[..]).unwrap_or_else(|| panic!("{op}: selector")).1;
            assert!(e.relayed && e.multi == multi && e.compact == compact, "{op}");
        }
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
