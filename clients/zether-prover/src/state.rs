//! Zether on raw storage words (ARCH-POS-13 "never a decryption oracle", owner 2026-11-06; ua-rs-sign T14b, spec
//! no-decryption-oracle §4.3, §4.7). Every command here that uses the key takes a named location and the **raw** storage
//! words a reading layer read at one block, never a ciphertext, an entry, a memo or a parsed state field: [`prepare`] checks the
//! location (`family`, `psid`, the reader's own `ua`), parses the words by the pinned layout ([`LAYOUT`], `ua-mtx-merge`
//! T19c `scaas.zether`), checks them (public data only), binds the selected leg and the role to the reader's key, and
//! rebuilds `acc`, `pending` and the entry record `R` exactly as `ZetherLib` stores them; only then does [`run`] use the
//! key. A refusal of [`prepare`] comes before any key use. Whether the words are real chain state of a catalogued token is
//! the reading layer's duty (R1–R7), not this crate's (spec §4.12): consistent fabricated words are rebuilt like real ones.
//!
//! The words, at one block (`R` the namespace root, `acct = keccak256(ua ‖ R + 8)`, a `bytes` at slot `S` long-form: the
//! length word `2·len + 1` at `S`, its data at `keccak256(S) + i`):
//! - `account`: the six slots of `acct[ua]` in slot order (`accC`, `accD`, `pendC`, `pendD` length words; the counters
//!   `accSeq ‖ pendingSeq ‖ lastRolledPendingSeq ‖ sendCounter`; `modeNonce ‖ mode`); `accountData`: `[{slot, word}]`, the
//!   data slots of every non-empty point among the four, in that order;
//! - an entry (`entryRef` recomputed from `fromUA` + `sendCounter`, as `ZetherLib.entryRefOf`): `entryWords` `[{slot, word}]`,
//!   the length slot of `entries[entryRef]` then its data slots; `entryPtr` the word of `entryPtrs[entryRef]`; when that is
//!   non-zero (commit-reveal), `blob` `{address, code}` (`eth_getCode` of the pointer: `0x00 ‖ R`) and `memoWords` (the
//!   length slot of `memos[entryRef]`, then its data slots);
//! - the token: `psid` (slot 6), `modes` (slot 0: `verifier(160) ‖ disclosureMode(8) ‖ auditorMode(8)`), `auditorKeyWords`
//!   (the length slot 5, then its data slots).
//!
//! UNAUDITED.

use rand_core::{CryptoRng, RngCore};
use serde_json::{json, Map, Value};

use crate::api::{bsgs_params, ct_json, hx, open_memo_with, prove_burn_with, prove_transfer_multi_with, prove_transfer_with, recover_transfer_with};
use crate::bulletproofs::Gens;
use crate::curve::{decode_point, keccak256, point_len, proof_system_id, ua_of, Bls12381, G};
use crate::elgamal::{cached_table, check_balance, BsgsParams, BsgsTable, Ciphertext};
use crate::keys::ZetherKey;
use crate::schnorr::{self, OpeningKind};

type R<T> = Result<T, String>;
type B = Bls12381;
type W = [u8; 32];

/// The namespace root of `scaas.zether` (`keccak256(abi.encode(uint256(keccak256("scaas.zether")) - 1)) & ~0xff`).
pub const ROOT: W = [
    0xd1, 0xee, 0xf6, 0xcb, 0xeb, 0x7b, 0x38, 0x3e, 0x0a, 0x92, 0xb3, 0xcb, 0x72, 0x30, 0x53, 0xd5, 0xc3, 0x9c, 0x76, 0x70, 0x7d,
    0x89, 0xda, 0x6b, 0x14, 0xff, 0x91, 0xb8, 0x31, 0x98, 0xce, 0x00,
];

/// The fields the words parse (`ZetherLib.ZetherStorage` / `Account`, pinned by T19c in `test/v2/layout/namespaces.json`;
/// `tests/state.rs` and ua-rs's `facade_zether_state.rs` compare this table with the pin the forge rows carry): `(label, slot,
/// inner, byte, width)`, `slot` in the namespace, `inner` the slot inside `acct[ua]`, `byte` counted from the low end of the
/// word (solc's packing).
pub const LAYOUT: &[(&str, u64, u64, usize, usize)] = &[
    ("disclosureMode", 0, 0, 20, 1),
    ("auditorMode", 0, 0, 21, 1),
    ("auditorKey", 5, 0, 0, 32),
    ("psid", 6, 0, 0, 32),
    ("acct[U].accC", 8, 0, 0, 32),
    ("acct[U].accD", 8, 1, 0, 32),
    ("acct[U].pendC", 8, 2, 0, 32),
    ("acct[U].pendD", 8, 3, 0, 32),
    ("acct[U].accSeq", 8, 4, 0, 8),
    ("acct[U].pendingSeq", 8, 4, 8, 8),
    ("acct[U].lastRolledPendingSeq", 8, 4, 16, 8),
    ("acct[U].sendCounter", 8, 4, 24, 8),
    ("entries[V]", 9, 0, 0, 32),
    ("entryPtrs[V]", 10, 0, 0, 20),
    ("memos[V]", 11, 0, 0, 32),
];

/// The families whose layout parser exists (EVM first; another family's words are refused until its parser exists).
pub const FAMILIES: &[&str] = &["evm"];

/// The commands on words, each with its allow-list ([`allowed`]).
pub const COMMANDS: &[&str] =
    &["balance", "pendingBalance", "checkBalance", "proveTransfer", "proveTransferMulti", "proveBurn", "openMemo", "recoverTransfer", "openDisclosure"];

const LOC: &[&str] = &["curve", "family", "chainId", "chainUid", "token", "block", "psid", "ua"];
const ACCT: &[&str] = &["account", "accountData"];
const BSGS: &[&str] = &["tableBits", "boundBits", "allowLargeTable"];
/// A debit's caller fields (encryption to public keys, the fee, the binding and the policy hints the chain checks again);
/// `sendCounter` and `accSeq` come from the words. `cacheBox`: the holder's own sealed balance-cache box `{iv, ct}` (clientkeys
/// `sealBalanceCache`, zether-limits D5; T15l, Fable P3-1: never a plain number), opened under the key, its entry
/// `<UA>:<token>` used only at the words' `accSeq` and checked against the rebuilt `acc` before proving (`[b]G == C − [x]D`);
/// without it, or with a stale entry, the balance is BSGS of the rebuilt `acc`.
const DEBIT: &[&str] = &["envelopeBinding", "fee", "beneficiary", "validUntilBlock", "disclosureMode", "auditorMode", "cacheBox"];
const ENTRY: &[&str] = &["fromUA", "sendCounter", "entryWords", "entryPtr", "blob", "memoWords"];
/// The fields that hold words (everything else is a caller field passed on to the prover).
const WORDS: &[&str] = &["family", "block", "psid", "ua", "account", "accountData", "fromUA", "entryWords", "entryPtr", "blob", "memoWords", "modes", "auditorKeyWords"];

/// The allow-list of `cmd`'s fields: never `key`, a ciphertext (`acc`, `ct`, `pending`), an entry, a memo, a payload or a
/// state field the words give (`accSeq`, a leg's points).
pub fn allowed(cmd: &str, field: &str) -> bool {
    let has = |l: &[&str]| l.contains(&field);
    let debit = |l: &[&str]| has(LOC) || has(ACCT) || has(DEBIT) || has(BSGS) || has(l);
    match cmd {
        "balance" | "pendingBalance" => has(LOC) || has(ACCT) || has(BSGS),
        "checkBalance" => has(LOC) || has(ACCT) || field == "cacheBox",
        "proveTransfer" => debit(&["yTo", "yAud", "amount"]),
        "proveTransferMulti" => debit(&["yAud", "mode", "recipients", "decoyFee", "minDecoyFee", "uaSigner", "uaSignerGas"]),
        "proveBurn" => debit(&["amount", "recipient", "unwrapBinding"]),
        "openMemo" => has(LOC) || has(ENTRY),
        "recoverTransfer" => has(LOC) || has(ENTRY) || has(BSGS) || field == "auditorKeyWords",
        "openDisclosure" => has(LOC) || has(ENTRY) || has(BSGS) || has(&["modes", "auditorKeyWords", "kind", "index"]),
        _ => false,
    }
}

// ------------------------------------------------------------------ words

fn get<'a>(v: &'a Value, k: &str) -> R<&'a Value> {
    v.get(k).filter(|x| !x.is_null()).ok_or_else(|| format!("missing `{k}`"))
}

fn hexb(x: &Value) -> R<Vec<u8>> {
    let s = x.as_str().ok_or("hex string expected")?;
    hex::decode(s.strip_prefix("0x").ok_or("0x hex expected")?).map_err(|_| "not hex".to_string())
}

fn word(x: &Value) -> R<W> {
    hexb(x)?.try_into().map_err(|_| "a word is 32 bytes".to_string())
}

fn wordf(v: &Value, k: &str) -> R<W> {
    word(get(v, k)?)
}

fn u64f(v: &Value, k: &str) -> R<u64> {
    get(v, k)?.as_u64().ok_or_else(|| format!("`{k}` must be a u64"))
}

fn slot_words(v: &Value, k: &str) -> R<Vec<(W, W)>> {
    get(v, k)?
        .as_array()
        .ok_or_else(|| format!("`{k}` must be [{{slot, word}}]"))?
        .iter()
        .map(|o| {
            if o.as_object().is_none_or(|m| m.len() != 2) {
                return Err(format!("`{k}`: {{slot, word}} expected"));
            }
            Ok((wordf(o, "slot")?, wordf(o, "word")?))
        })
        .collect()
}

/// `a + i` (mod 2^256), big-endian.
fn add(a: &W, i: u64) -> W {
    let mut o = *a;
    let mut carry = u128::from(i);
    for b in o.iter_mut().rev() {
        let t = u128::from(*b) + (carry & 0xff);
        *b = t as u8;
        carry = (carry >> 8) + (t >> 8);
    }
    o
}

/// The layout row of `label`.
fn lay(label: &str) -> R<(u64, u64, usize, usize)> {
    LAYOUT.iter().find(|r| r.0 == label).map(|r| (r.1, r.2, r.3, r.4)).ok_or_else(|| format!("no layout row {label}"))
}

/// The namespace slot of `label` (`R + slot`).
fn ns(label: &str) -> R<W> {
    Ok(add(&ROOT, lay(label)?.0))
}

/// `keccak256(key ‖ base)`: a mapping's value slot.
fn map_slot(key: &W, base: &W) -> W {
    keccak256(&[key.as_slice(), base.as_slice()].concat())
}

/// The field `label` of word `w` (its `width` bytes at `byte` from the low end), as a big-endian u64 (width ≤ 8).
fn field_u64(w: &W, label: &str) -> R<u64> {
    let (_, _, byte, width) = lay(label)?;
    let end = 32usize.checked_sub(byte).ok_or("layout")?;
    let b = w.get(end.checked_sub(width).ok_or("layout")?..end).ok_or("layout")?;
    if width > 8 {
        return Err("layout".into());
    }
    Ok(b.iter().fold(0u64, |a, x| (a << 8) | u64::from(*x)))
}

/// The bytes at slot `s` from `words` (`[{slot, word}]`): the length word `len` at `s` (`with_len`; else `len_word` is
/// given), then exactly the data slots `keccak256(s) + i` of a long-form `bytes`, in order. Empty: the length word 0 and no
/// data slot. A short form (a value under 32 bytes, none of the fields here) is refused.
fn bytes_at(s: &W, len_word: &W, data: &[(W, W)]) -> R<Vec<u8>> {
    if *len_word == [0; 32] {
        return if data.is_empty() { Ok(vec![]) } else { Err("words past an empty bytes".into()) };
    }
    if len_word[31] & 1 == 0 || len_word[..24].iter().any(|b| *b != 0) {
        return Err("not a long-form bytes length".into());
    }
    let len = usize::try_from((u64::from_be_bytes(len_word[24..].try_into().map_err(|_| "len")?) - 1) / 2).map_err(|_| "len")?;
    let n = len.div_ceil(32);
    if len < 32 || data.len() != n {
        return Err("data slots of a bytes: wrong count".into());
    }
    let d = keccak256(s);
    let mut out = Vec::with_capacity(n * 32);
    for (i, (slot, w)) in data.iter().enumerate() {
        if *slot != add(&d, i as u64) {
            return Err("data slot out of place".into());
        }
        out.extend_from_slice(w);
    }
    out.truncate(len);
    Ok(out)
}

/// A `bytes` given as one `[{slot, word}]` list: its length slot `s` first, then its data slots.
fn bytes_list(s: &W, list: &[(W, W)]) -> R<Vec<u8>> {
    let ((slot, len), data) = list.split_first().ok_or("empty word list")?;
    if slot != s {
        return Err("length slot out of place".into());
    }
    bytes_at(s, len, data)
}

/// A stored point (`bytes`, empty = `O`), strictly decoded.
fn point(b: &[u8]) -> R<G<B>> {
    if b.is_empty() {
        return Ok(G::<B>::default());
    }
    if b.len() != point_len::<B>() {
        return Err("a point is 128 bytes".into());
    }
    decode_point::<B>(b).map_err(|e| e.to_string())
}

/// An account rebuilt from `account` and `accountData` at `acct[ua]`.
#[derive(Clone)]
pub struct Account {
    pub acc: Ciphertext<B>,
    pub pending: Ciphertext<B>,
    pub acc_seq: u64,
    pub pending_seq: u64,
    pub last_rolled_pending_seq: u64,
    pub send_counter: u64,
}

fn account(v: &Value, ua: &W) -> R<Account> {
    let words: Vec<W> = get(v, "account")?.as_array().ok_or("`account` must be [word]")?.iter().map(word).collect::<R<_>>()?;
    if words.len() != 6 {
        return Err("`account` is the six slots of acct[ua]".into());
    }
    let base = map_slot(ua, &ns("acct[U].accC")?);
    let data = slot_words(v, "accountData")?;
    let mut rest = data.as_slice();
    let mut pts = Vec::with_capacity(4);
    for label in ["acct[U].accC", "acct[U].accD", "acct[U].pendC", "acct[U].pendD"] {
        let inner = lay(label)?.1;
        let lw = words.get(inner as usize).ok_or("layout")?;
        let n = if *lw == [0; 32] { 0 } else { point_len::<B>().div_ceil(32) };
        let (mine, tail) = rest.split_at_checked(n).ok_or("`accountData`: too few words")?;
        rest = tail;
        pts.push(point(&bytes_at(&add(&base, inner), lw, mine)?)?);
    }
    if !rest.is_empty() {
        return Err("`accountData`: extra words".into());
    }
    let counters = words.get(lay("acct[U].accSeq")?.1 as usize).ok_or("layout")?;
    let a = Account {
        acc: Ciphertext { c: pts[0], d: pts[1] },
        pending: Ciphertext { c: pts[2], d: pts[3] },
        acc_seq: field_u64(counters, "acct[U].accSeq")?,
        pending_seq: field_u64(counters, "acct[U].pendingSeq")?,
        last_rolled_pending_seq: field_u64(counters, "acct[U].lastRolledPendingSeq")?,
        send_counter: field_u64(counters, "acct[U].sendCounter")?,
    };
    // a roll-over deletes `pending` (`ZetherLib._rollOver`): nothing new since the last one means `O`
    if a.pending_seq < a.last_rolled_pending_seq || (a.pending_seq == a.last_rolled_pending_seq && a.pending != Ciphertext::zero()) {
        return Err("pending counters inconsistent with pending".into());
    }
    Ok(a)
}

/// A stored entry rebuilt from its words: `R = salt ‖ B_1 ‖ … ‖ B_M` and, on commit-reveal, the memo `salt ‖ sealed`.
#[derive(Clone)]
pub struct Entry {
    pub entry_ref: W,
    pub from: W,
    pub send_counter: u64,
    pub record: Vec<u8>,
    pub memo: Option<Vec<u8>>,
    pub single: bool,
    pub m: usize,
}

impl Entry {
    /// Leg `j`: `(Y_t, C_out, D_out, C_aud, D_aud)` as `ZetherDisclosure._leg` (`D_aud = D_out` on the single format).
    pub fn leg(&self, j: usize) -> R<[G<B>; 5]> {
        let p = point_len::<B>();
        let stride = if self.single { 4 * p } else { 5 * p };
        if j >= self.m {
            return Err("leg outside the entry".into());
        }
        let o = 16 + j * stride;
        let pt = |k: usize| point(self.record.get(o + k * p..o + (k + 1) * p).ok_or("record")?);
        Ok([pt(0)?, pt(1)?, pt(2)?, pt(3)?, if self.single { pt(2)? } else { pt(4)? }])
    }
}

fn entry(v: &Value, chain_id: u64, chain_uid: &W, token: &[u8; 20]) -> R<Entry> {
    let p = point_len::<B>();
    let from = wordf(v, "fromUA")?;
    let send_counter = u64f(v, "sendCounter")?;
    let entry_ref = schnorr::entry_ref(chain_id, chain_uid, token, &from, send_counter);
    let inline = bytes_list(&map_slot(&entry_ref, &ns("entries[V]")?), &slot_words(v, "entryWords")?)?;
    let ptr_word = wordf(v, "entryPtr")?;
    let has = |k: &str| v.get(k).is_some_and(|x| !x.is_null());
    let (record, memo) = if ptr_word == [0; 32] {
        if inline.is_empty() || has("blob") || has("memoWords") {
            return Err("an inline entry has its record and no blob or memo".into());
        }
        (inline, None)
    } else {
        let (_, _, byte, width) = lay("entryPtrs[V]")?;
        let at = 32 - byte - width;
        if !inline.is_empty() || ptr_word[..at].iter().any(|b| *b != 0) {
            return Err("a commit-reveal entry has a pointer and no inline record".into());
        }
        let b = get(v, "blob")?;
        if b.as_object().is_none_or(|o| o.len() != 2) || hexb(get(b, "address")?)? != ptr_word[at..] {
            return Err("`blob` is {address, code} of entryPtr".into());
        }
        let code = hexb(get(b, "code")?)?;
        let (stop, r) = code.split_first().ok_or("empty code")?;
        if *stop != 0 {
            return Err("not an SSTORE2 code".into());
        }
        let memo = bytes_list(&map_slot(&entry_ref, &ns("memos[V]")?), &slot_words(v, "memoWords")?)?;
        (r.to_vec(), Some(memo))
    };
    let single = record.len() == 16 + 4 * p;
    let m = if single { 1 } else { record.len().saturating_sub(16) / (5 * p) };
    if !single && (record.len() <= 16 || (record.len() - 16) % (5 * p) != 0 || m > crate::zether::MAX_RECIPIENTS) {
        return Err("not a record R".into());
    }
    if let Some(memo) = &memo {
        if single || memo.len() != crate::zether::memo_len(m) || memo.get(..16) != record.get(..16) {
            return Err("the memo is not this record's".into());
        }
    }
    Ok(Entry { entry_ref, from, send_counter, record, memo, single, m })
}

/// The token's auditor key (`auditorKeyWords`): `O` when the token has none.
fn auditor_key(v: &Value) -> R<G<B>> {
    point(&bytes_list(&ns("auditorKey")?, &slot_words(v, "auditorKeyWords")?)?)
}

// ------------------------------------------------------------------ prepare, run

/// A command whose words are parsed, checked and bound to the reader; [`run`] uses the key.
pub struct Prepared {
    cmd: &'static str,
    /// The caller fields (the words removed).
    fields: Map<String, Value>,
    chain_id: u64,
    chain_uid: W,
    token: [u8; 20],
    account: Option<Account>,
    entry: Option<Entry>,
    y_aud: G<B>,
}

impl Prepared {
    pub fn cmd(&self) -> &'static str {
        self.cmd
    }
    pub fn account(&self) -> Option<&Account> {
        self.account.as_ref()
    }
    pub fn entry(&self) -> Option<&Entry> {
        self.entry.as_ref()
    }
}

/// `cmd` of [`COMMANDS`] on `v` for the reader with public key `y` (UA `ua_of(y)`): every field on the allow-list, the
/// location checked, the words parsed and checked, the leg and the role bound to `y`, the ciphertexts rebuilt. Public data
/// only: the key is not touched.
pub fn prepare(cmd: &str, v: &Value, y: &G<B>) -> R<Prepared> {
    let cmd = *COMMANDS.iter().find(|c| **c == cmd).ok_or("unknown command")?;
    let o = v.as_object().ok_or("a JSON object expected")?;
    if let Some(k) = o.keys().find(|k| !allowed(cmd, k)) {
        return Err(format!("`{k}` is not a field of `{cmd}`"));
    }
    if o.get("curve").is_some_and(|c| c.as_str() != Some("bls12381")) {
        return Err("curve must be bls12381".into());
    }
    if !FAMILIES.contains(&get(v, "family")?.as_str().ok_or("`family` must be a string")?) {
        return Err("no layout parser for this family".into());
    }
    u64f(v, "block")?;
    if wordf(v, "psid")? != proof_system_id::<B>() {
        return Err("`psid` is not this prover's".into());
    }
    let ua = ua_of::<B>(y);
    if wordf(v, "ua")? != ua {
        return Err("`ua` is not the reader's".into());
    }
    let chain_id = u64f(v, "chainId")?;
    let chain_uid = wordf(v, "chainUid")?;
    let token: [u8; 20] = hexb(get(v, "token")?)?.try_into().map_err(|_| "`token` is 20 bytes")?;
    let mut p = Prepared {
        cmd,
        fields: o.iter().filter(|(k, _)| !WORDS.contains(&k.as_str())).map(|(k, x)| (k.clone(), x.clone())).collect(),
        chain_id,
        chain_uid,
        token,
        account: None,
        entry: None,
        y_aud: G::<B>::default(),
    };
    match cmd {
        "openMemo" | "recoverTransfer" | "openDisclosure" => {
            let e = entry(v, chain_id, &chain_uid, &token)?;
            if cmd != "openDisclosure" && e.from != ua {
                return Err("a sender's command reads the reader's own entries".into());
            }
            if cmd == "openMemo" && e.memo.is_none() {
                return Err("no memo: not a commit-reveal entry".into());
            }
            if cmd == "recoverTransfer" {
                p.y_aud = auditor_key(v)?;
            }
            if cmd == "openDisclosure" {
                let j = usize::try_from(u64f(v, "index")?).map_err(|_| "`index`")?;
                let leg = e.leg(j)?;
                match get(v, "kind")?.as_str() {
                    Some("receiver") if leg[0] == *y => {}
                    Some("auditor") => {
                        let modes = wordf(v, "modes")?;
                        p.y_aud = auditor_key(v)?;
                        if field_u64(&modes, "auditorMode")? == 0 || p.y_aud != *y || leg[3] == G::<B>::default() {
                            return Err("not the auditor of this leg".into());
                        }
                    }
                    _ => return Err("not the receiver of this leg".into()),
                }
            }
            p.entry = Some(e);
        }
        _ => p.account = Some(account(v, &ua)?),
    }
    Ok(p)
}

fn amount_of(ct: &Ciphertext<B>, k: &ZetherKey<B>, v: &Value, d: BsgsParams) -> R<u64> {
    let bp = bsgs_params::<B>(v, d)?;
    cached_table::<B>(bp.table_bits).map_err(|e| e.to_string())?.decrypt(ct, &k.x, bp.bound_bits).map_err(|e| e.to_string())
}

/// [`prepare`]'s command with the key `k` (the holder's or the auditor's): its JSON answer.
pub fn run<Rn: RngCore + CryptoRng>(p: &Prepared, k: &ZetherKey<B>, rng: &mut Rn) -> R<Value> {
    let f = Value::Object(p.fields.clone());
    let chain = |m: &mut Map<String, Value>| {
        m.insert("curve".into(), json!("bls12381"));
        m.insert("chainId".into(), json!(p.chain_id));
        m.insert("chainUid".into(), json!(hx(&p.chain_uid)));
        m.insert("token".into(), json!(hx(&p.token)));
    };
    if let Some(a) = &p.account {
        let counters = json!({"accSeq": a.acc_seq, "pendingSeq": a.pending_seq, "lastRolledPendingSeq": a.last_rolled_pending_seq,
            "sendCounter": a.send_counter});
        return match p.cmd {
            "balance" => Ok(json!({"amount": amount_of(&a.acc, k, &f, BsgsParams::for_target())?.to_string(), "state": counters})),
            "pendingBalance" => Ok(json!({"amount": amount_of(&a.pending, k, &f, BsgsParams::MOBILE)?.to_string(), "state": counters})),
            "checkBalance" => {
                // the holder's own cached balance (its sealed box), at the words' `accSeq`, against the rebuilt `acc`
                let (b, seq) = open_cache_entry(k, get(&f, "cacheBox")?, &p.token)?;
                let ok = seq == a.acc_seq && check_balance(&a.acc, &k.x, b).map_err(|e| e.to_string())?;
                Ok(json!({"ok": ok, "state": counters}))
            }
            _ => {
                let mut m = p.fields.clone();
                let hint = match m.remove("cacheBox") {
                    Some(bx) => {
                        let (b, seq) = open_cache_entry(k, &bx, &p.token)?;
                        (seq == a.acc_seq).then_some(b)
                    }
                    None => None,
                };
                let b = match hint {
                    Some(b) => b,
                    None => amount_of(&a.acc, k, &f, BsgsParams::for_target())?,
                };
                m.insert("balance".into(), json!(b.to_string()));
                for x in BSGS {
                    m.remove(*x);
                }
                chain(&mut m);
                m.insert("acc".into(), ct_json::<B>(&a.acc));
                m.insert("sendCounter".into(), json!(a.send_counter));
                m.insert("accSeq".into(), json!(a.acc_seq));
                let raw = Value::Object(m);
                let gens = Gens::<B>::new();
                match p.cmd {
                    "proveTransfer" => prove_transfer_with::<B, _>(&gens, Some(k), &raw, rng),
                    "proveTransferMulti" => prove_transfer_multi_with::<B, _>(&gens, Some(k), &raw, rng),
                    _ => prove_burn_with::<B, _>(&gens, Some(k), &raw, rng),
                }
            }
        };
    }
    let e = p.entry.as_ref().ok_or("no words")?;
    let mut m = Map::new();
    chain(&mut m);
    m.insert("entry".into(), json!(hx(&e.record)));
    m.insert("sendCounter".into(), json!(e.send_counter));
    if let Some(memo) = &e.memo {
        m.insert("memo".into(), json!(hx(memo)));
    }
    match p.cmd {
        "openMemo" => open_memo_with::<B>(Some(k), &Value::Object(m)),
        "recoverTransfer" => {
            for x in BSGS {
                if let Some(b) = p.fields.get(*x) {
                    m.insert((*x).into(), b.clone());
                }
            }
            if p.y_aud != G::<B>::default() {
                m.insert("yAud".into(), json!(hx(&crate::curve::encode_point::<B>(&p.y_aud))));
            }
            recover_transfer_with::<B, _>(Some(k), &Value::Object(m), rng)
        }
        _ => {
            let j = u64f(&f, "index")?;
            let [y_t, c_out, d_out, c_aud, d_aud] = e.leg(usize::try_from(j).map_err(|_| "`index`")?)?;
            let (kind, ct) = match get(&f, "kind")?.as_str() {
                Some("auditor") => (OpeningKind::Auditor, Ciphertext { c: c_aud, d: d_aud }),
                _ => (OpeningKind::ReceiverX, Ciphertext { c: c_out, d: d_out }),
            };
            let amount = amount_of(&ct, k, &f, BsgsParams::for_target())?;
            let leg = schnorr::Entry {
                chain_id: p.chain_id,
                chain_uid: p.chain_uid,
                token: p.token,
                entry_ref: e.entry_ref,
                index: j,
                y_t,
                c_out,
                d_out,
                y_a: p.y_aud,
                c_aud,
                d_aud,
            };
            let opening = schnorr::open_chaum_pedersen(&leg, amount, kind, k, rng).map_err(|e| e.to_string())?;
            Ok(json!({"kind": kind as u8, "amount": amount.to_string(), "entryRef": hx(&e.entry_ref), "opening": hx(&opening)}))
        }
    }
}

/// zether.js `CACHE_INFO` and the AAD of `sealBalanceCache` on BLS12-381.
const CACHE_INFO: &[u8] = b"scaas-zether-balance-cache-v1";
const CACHE_AAD: &[u8] = b"zether-cache:bls12381";

/// Unpadded base64url (the box's `iv` and `ct`).
fn b64url(s: &str) -> R<Vec<u8>> {
    let val = |c: u8| match c {
        b'A'..=b'Z' => Ok(c - b'A'),
        b'a'..=b'z' => Ok(c - b'a' + 26),
        b'0'..=b'9' => Ok(c - b'0' + 52),
        b'-' => Ok(62),
        b'_' => Ok(63),
        _ => Err("not base64url".to_string()),
    };
    let (mut out, mut acc, mut n) = (Vec::new(), 0u32, 0);
    for c in s.bytes() {
        acc = (acc << 6) | u32::from(val(c)?);
        n += 6;
        if n >= 8 {
            n -= 8;
            out.push((acc >> n) as u8);
        }
    }
    Ok(out)
}

/// The holder's entry `<UA>:<token>` (lowercase `0x` hex) of its sealed balance-cache box `{iv, ct}` (clientkeys
/// `sealBalanceCache`: AES-256-GCM under `HKDF-SHA256(x, no salt, "scaas-zether-balance-cache-v1", 32)`, AAD
/// `zether-cache:bls12381`): `(balance, accSeq)`. A box that does not open under `k`, or holds no such entry, is refused. No
/// outsider can make a box that opens (T15l, Fable P3-1: the balance hint is the holder's own, never a caller's number).
pub fn open_cache_entry(k: &ZetherKey<B>, bx: &Value, token: &[u8; 20]) -> R<(u64, u64)> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    if bx.as_object().is_none_or(|o| o.len() != 2) {
        return Err("the cache box is {iv, ct}".into());
    }
    let field = |f: &str| b64url(get(bx, f)?.as_str().ok_or("the cache box's fields are base64url")?);
    let iv: [u8; 12] = field("iv")?.try_into().map_err(|_| "a 12-byte iv")?;
    let x = zeroize::Zeroizing::new(crate::curve::encode_scalar::<B>(&k.x));
    let mut ck = zeroize::Zeroizing::new([0u8; 32]);
    hkdf::Hkdf::<sha2::Sha256>::new(None, &x[..]).expand(CACHE_INFO, &mut ck[..]).map_err(|_| "hkdf")?;
    let pt = zeroize::Zeroizing::new(
        aes_gcm::Aes256Gcm::new_from_slice(&ck[..])
            .map_err(|_| "aes")?
            .decrypt(&aes_gcm::Nonce::from(iv), Payload { msg: &field("ct")?, aad: CACHE_AAD })
            .map_err(|_| "the cache box does not open under this key")?,
    );
    let entries: Value = serde_json::from_slice(&pt).map_err(|_| "the cache entries are not JSON")?;
    let e = entries.get(format!("{}:{}", hx(&k.ua()), hx(token))).ok_or("no entry for this key's UA and token")?;
    let n = |f: &str| match &e[f] {
        Value::String(s) => s.parse::<u64>().map_err(|_| format!("cache `{f}`")),
        x => x.as_u64().ok_or(format!("cache `{f}`")),
    };
    Ok((n("balance")?, n("accSeq")?))
}

/// [`prepare`]'s `balance` (`acc`) or `pendingBalance` (`pending`) by BSGS on the caller's own table (public data; e.g.
/// `zether-read-balance --table-file`), bound `2^bound_bits`.
pub fn amount_with_table(p: &Prepared, k: &ZetherKey<B>, t: &BsgsTable<B>, bound_bits: u32) -> R<u64> {
    let a = p.account.as_ref().ok_or("not an account command")?;
    let ct = match p.cmd {
        "balance" => &a.acc,
        "pendingBalance" => &a.pending,
        _ => return Err("not a balance command".into()),
    };
    t.decrypt(ct, &k.x, bound_bits).map_err(|e| e.to_string())
}

/// [`prepare`] then [`run`]: `cmd` on the words of `v` with the key `k`.
pub fn call_with_key<Rn: RngCore + CryptoRng>(cmd: &str, v: &Value, k: &ZetherKey<B>, rng: &mut Rn) -> R<Value> {
    run(&prepare(cmd, v, &k.y)?, k, rng)
}

#[cfg(test)]
mod tests {
    #[test]
    fn b64url_decodes() {
        assert_eq!(super::b64url("AQIDBA").unwrap(), [1, 2, 3, 4]);
        assert!(super::b64url("AQ=").is_err());
    }
}
