// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! CTR-CHAT-27 (spec 2026-11-23-pqchat-treekem §8, §15; C37; fable-r3-6, codex-r3-12; plan T4): the node's whole-set guard of a
//! tree commit and the order it sends the set in. Pure: the hashes, the admission check, what to send next from what is in
//! state; `crate::submit` reads the state and sends. UNAUDITED.
//!
//! A tree commit travels as one `commit` job holding every piece its record signs: the list, the node keys, every path
//! ciphertext, every Welcome wrap. Before anything is sent each piece must hash to its signed hash and every node key pass the
//! admission check (C19, C32), else [`TREE_SET_REFUSED`] and zero sends. The set leaves in the order of C37: the whole commit as
//! one transaction when it fits; else the record, then the list, then the node keys, each final before the next, then the other
//! ciphertexts and the wraps, and one piece held back (the last ciphertext, else the last wrap) sent alone, last, as the job's
//! own transaction, once everything else is final. A piece job on its own (`addPathList`, `addPathKeys`, `addPath`, a tree
//! commit's `addWraps`) is relayed only when, with it, nothing the record signs is missing from state.
use crate::typed::{parse, struct_hash_of};
use alloy::primitives::{keccak256, B256, U256};
use alloy::sol_types::SolValue;
use serde_json::{json, Value};

/// A set (or a piece) that cannot complete as given: a piece missing, a hash that is not the signed one, a node key the
/// contract would not admit, or a record that does not fit a transaction alone. Nothing is sent.
pub const TREE_SET_REFUSED: &str = "TREE_SET_REFUSED";
/// A set in flight: a part was sent, or one is not final yet; the job waits `queued`.
pub const TREE_SET_SENDING: &str = "TREE_SET_SENDING";
/// A piece job on its own whose record still misses other pieces: it waits for them (another sender may land them).
pub const TREE_SET_WAITING: &str = "TREE_SET_WAITING";

/// A node key: `0x01 ‖ ek ‖ pk_X`.
const KEM_PK: usize = 1601;
/// `p = 2^255 − 19`, little-endian.
const P25519: [u8; 32] = {
    let mut p = [0xff; 32];
    p[0] = 0xed;
    p[31] = 0x7f;
    p
};
/// The canonical small-order X25519 values: 0, 1, the two of order 8, p − 1 (little-endian), as `PqGroupTree._admissible`.
const SMALL_ORDER: [[u8; 32]; 5] = [
    [0; 32],
    {
        let mut o = [0; 32];
        o[0] = 1;
        o
    },
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ],
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ],
    {
        let mut p = [0xff; 32];
        p[0] = 0xec;
        p[31] = 0x7f;
        p
    },
];

/// `PqGroupTree._admissible` (C19, C32): scheme byte 1, 1,601 B, every `ek` coefficient below 3,329, `pk_X` below p (so bit
/// 255 clear) and of none of the five small orders.
pub fn admissible(pk: &[u8]) -> bool {
    if pk.len() != KEM_PK || pk[0] != 1 {
        return false;
    }
    let lt_q = |c: &[u8]| {
        (u16::from(c[0]) | u16::from(c[1] & 15) << 8) < 3329
            && (u16::from(c[1] >> 4) | u16::from(c[2]) << 4) < 3329
    };
    if !pk[1..1537].chunks(3).all(lt_q) {
        return false;
    }
    let mut x = [0u8; 32];
    x.copy_from_slice(&pk[1569..]);
    x.iter().rev().cmp(P25519.iter().rev()) == std::cmp::Ordering::Less && !SMALL_ORDER.contains(&x)
}

/// `PqChatTypes.epochId`: `keccak256(abi.encode(TAG_EPOCH, sessionId, author, nonce))`.
pub fn epoch_id(session: B256, author: B256, nonce: u64) -> B256 {
    keccak256(
        (
            keccak256("scaas/pqchat/v1/epoch"),
            session,
            author,
            U256::from(nonce),
        )
            .abi_encode(),
    )
}

fn arr(v: &Value) -> &[Value] {
    v.as_array().map_or(&[], Vec::as_slice)
}

fn b32(v: &Value) -> Option<B256> {
    v.as_str()?.parse().ok()
}

fn num(v: &Value) -> Option<u64> {
    v.as_u64().or_else(|| v.as_str()?.parse().ok())
}

/// `hashStruct` of a named value of a nested struct (the typed rows', `crate::typed`).
pub fn hash(ty: &str, v: &Value) -> Option<B256> {
    struct_hash_of(ty, &parse(ty, v, ty).ok()?)
}

/// `hashPathList` of a list: `ctTargets` and `ctHashes` as the `PathList` struct.
pub fn list_hash(ct_targets: &Value, ct_hashes: &Value) -> Option<B256> {
    hash(
        "PathList",
        &json!({"ctTargets": ct_targets, "ctHashes": ct_hashes}),
    )
}

/// A `commit` job's set, checked whole: its named `args` (`c`, `ctTargets`, `ctHashes`, `nodeKeys`, `cts`, `wraps`, `sig`).
#[derive(Debug, Clone)]
pub struct Set {
    pub eid: B256,
    pub args: Value,
    pub cts: usize,
    pub keys: usize,
    pub adds: usize,
}

/// The whole-set guard of a `commit` job (fable-r3-6): every piece its record signs is held, hashes to its signed hash, and
/// every node key passes the admission check. The error names the first piece that fails.
pub fn whole(args: &Value) -> Result<Set, String> {
    let c = &args["c"];
    let bad = |what: String| Err(format!("{TREE_SET_REFUSED}: {what}; nothing sent"));
    let (Some(cts), Some(sid), Some(author), Some(nonce)) = (
        num(&c["ctCount"]),
        b32(&c["sessionId"]),
        b32(&c["author"]),
        num(&c["nonce"]),
    ) else {
        return bad("the record's fields unread".into());
    };
    let cts = cts as usize;
    let key_hashes = arr(&c["nodeKeyHashes"]);
    let wrap_hashes = arr(&c["wrapHashes"]);
    let adds = arr(&c["adds"]).len();
    let ct_hashes = arr(&args["ctHashes"]);
    if cts > 0 {
        if arr(&args["ctTargets"]).len() != cts || ct_hashes.len() != cts {
            return bad(format!(
                "the list: {cts} entries signed, {} held",
                ct_hashes.len()
            ));
        }
        if list_hash(&args["ctTargets"], &args["ctHashes"]) != b32(&c["ctListHash"]) {
            return bad("the list does not hash to ctListHash".into());
        }
    }
    let keys = arr(&args["nodeKeys"]);
    if keys.len() != key_hashes.len() {
        return bad(format!(
            "node keys: {} signed, {} held",
            key_hashes.len(),
            keys.len()
        ));
    }
    for (k, (nk, h)) in keys.iter().zip(key_hashes).enumerate() {
        let pk = nk
            .as_str()
            .and_then(|s| alloy::hex::decode(s).ok())
            .unwrap_or_default();
        if Some(keccak256(&pk)) != b32(h) {
            return bad(format!("node key {k} does not hash to nodeKeyHashes[{k}]"));
        }
        if !admissible(&pk) {
            return bad(format!("node key {k} fails the admission check"));
        }
    }
    let path = arr(&args["cts"]);
    if path.len() != cts {
        return bad(format!(
            "path ciphertexts: {cts} signed, {} held",
            path.len()
        ));
    }
    for (i, (ct, h)) in path.iter().zip(ct_hashes).enumerate() {
        if hash("PathCt", ct) != b32(h) {
            return bad(format!("ciphertext {i} does not hash to ctHashes[{i}]"));
        }
    }
    let wraps = arr(&args["wraps"]);
    if wraps.len() != adds {
        return bad(format!(
            "Welcome wraps: {adds} signed, {} held",
            wraps.len()
        ));
    }
    for (i, (w, h)) in wraps.iter().zip(wrap_hashes).enumerate() {
        if hash("Wrap", w) != b32(h) {
            return bad(format!("Welcome wrap {i} does not hash to wrapHashes[{i}]"));
        }
    }
    Ok(Set {
        eid: epoch_id(sid, author, nonce),
        args: args.clone(),
        cts,
        keys: key_hashes.len(),
        adds,
    })
}

/// What of a set is in state at one block.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Landed {
    pub record: bool,
    pub list: bool,
    pub keys: bool,
    pub cts: Vec<bool>,
    pub wraps: Vec<bool>,
}

impl Landed {
    /// Everything of `s` in state (its record, list, keys, ciphertexts and wraps).
    pub fn all(s: &Set) -> Self {
        Landed {
            record: true,
            list: s.cts > 0,
            keys: s.keys > 0,
            cts: vec![true; s.cts],
            wraps: vec![true; s.adds],
        }
    }
}

/// What to do next with a set, from what is in state at the head (`latest`) and at the final block (`fin`).
#[derive(Debug, Clone, PartialEq)]
pub enum Step {
    /// Nothing in state: the whole commit as the job's own transaction when it fits, else [`record_alone`] first.
    Whole,
    /// Send these parts (`(entry, args)`) now; the job waits.
    Parts(Vec<(&'static str, Value)>),
    /// Nothing to send until a part lands or is final.
    Wait(String),
    /// The held piece, alone, last: the job's own transaction.
    Last(&'static str, Value),
    /// Every piece is in state: the commit is complete.
    Done,
}

/// The piece held back (C37): the last path ciphertext, else the last Welcome wrap; `None` for a commit with no piece.
fn held(s: &Set) -> Option<(bool, usize)> {
    if s.cts > 0 {
        Some((true, s.cts - 1))
    } else {
        (s.adds > 0).then(|| (false, s.adds - 1))
    }
}

/// The `[a, b)` runs of the indices below `n` that `missing` holds, `skip` left out.
fn runs(n: usize, missing: impl Fn(usize) -> bool, skip: Option<usize>) -> Vec<(usize, usize)> {
    let mut out: Vec<(usize, usize)> = Vec::new();
    for i in (0..n).filter(|i| Some(*i) != skip && missing(*i)) {
        match out.last_mut() {
            Some(r) if r.1 == i => r.1 = i + 1,
            _ => out.push((i, i + 1)),
        }
    }
    out
}

fn path_op(s: &Set, a: usize, b: usize) -> Value {
    json!({"epochId": format!("{:#x}", s.eid), "firstCt": a.to_string(), "cts": arr(&s.args["cts"])[a..b]})
}

fn wraps_op(s: &Set, a: usize, b: usize) -> Value {
    json!({"epochId": format!("{:#x}", s.eid), "first": a.to_string(), "wraps": arr(&s.args["wraps"])[a..b]})
}

/// The record alone: `commit` with every piece array empty (C37's first transaction when the whole does not fit).
pub fn record_alone(s: &Set) -> Value {
    json!({"c": s.args["c"], "ctTargets": [], "ctHashes": [], "nodeKeys": [], "cts": [], "wraps": [], "sig": s.args["sig"]})
}

/// C37: the record, then the list, then the node keys, each final before the next; then the other ciphertexts and the wraps;
/// then the held piece alone once every other piece is final. A part landed but not final is waited for, never sent again.
pub fn step(s: &Set, latest: &Landed, fin: &Landed) -> Step {
    if !latest.record {
        return Step::Whole;
    }
    if !fin.record {
        return Step::Wait("the record is not final".into());
    }
    let eid = format!("{:#x}", s.eid);
    if s.cts > 0 {
        if !latest.list {
            return Step::Parts(vec![(
                "addPathList",
                json!({"epochId": eid, "ctTargets": s.args["ctTargets"], "ctHashes": s.args["ctHashes"]}),
            )]);
        }
        if !fin.list {
            return Step::Wait("the list is not final".into());
        }
    }
    if s.keys > 0 {
        if !latest.keys {
            return Step::Parts(vec![(
                "addPathKeys",
                json!({"epochId": eid, "nodeKeys": s.args["nodeKeys"]}),
            )]);
        }
        if !fin.keys {
            return Step::Wait("the node keys are not final".into());
        }
    }
    let h = held(s);
    let (ct_skip, wrap_skip) = match h {
        Some((true, i)) => (Some(i), None),
        Some((false, i)) => (None, Some(i)),
        None => (None, None),
    };
    let at = |v: &[bool], i: usize| v.get(i).copied().unwrap_or(false);
    let mut parts: Vec<(&'static str, Value)> = runs(s.cts, |i| !at(&latest.cts, i), ct_skip)
        .into_iter()
        .map(|(a, b)| ("addPath", path_op(s, a, b)))
        .collect();
    parts.extend(
        runs(s.adds, |i| !at(&latest.wraps, i), wrap_skip)
            .into_iter()
            .map(|(a, b)| ("addWraps", wraps_op(s, a, b))),
    );
    if !parts.is_empty() {
        return Step::Parts(parts);
    }
    let rest_final = (0..s.cts).all(|i| Some(i) == ct_skip || at(&fin.cts, i))
        && (0..s.adds).all(|i| Some(i) == wrap_skip || at(&fin.wraps, i));
    match h {
        Some((true, i)) if !at(&latest.cts, i) => {
            if !rest_final {
                return Step::Wait("the other pieces are not final".into());
            }
            Step::Last("addPath", path_op(s, i, i + 1))
        }
        Some((false, i)) if !at(&latest.wraps, i) => {
            if !rest_final {
                return Step::Wait("the other pieces are not final".into());
            }
            Step::Last("addWraps", wraps_op(s, i, i + 1))
        }
        _ => Step::Done,
    }
}

/// A part of more than one ciphertext or wrap split in two halves (a part over the transaction cap is sent as halves).
pub fn halve(entry: &str, args: &Value) -> Option<(Value, Value)> {
    let (list, first) = match entry {
        "addPath" => ("cts", "firstCt"),
        "addWraps" => ("wraps", "first"),
        _ => return None,
    };
    let v = arr(&args[list]);
    let a = num(&args[first])? as usize;
    (v.len() > 1).then(|| {
        let m = v.len() / 2;
        let mut lo = args.clone();
        let mut hi = args.clone();
        lo[list] = Value::Array(v[..m].to_vec());
        hi[list] = Value::Array(v[m..].to_vec());
        hi[first] = json!((a + m).to_string());
        (lo, hi)
    })
}

/// The signed hashes of a stored record (`commitOf`) a piece on its own is checked against.
#[derive(Debug, Clone, Default)]
pub struct Rec {
    pub cts: usize,
    pub list_hash: B256,
    pub key_hashes: Vec<B256>,
    pub wrap_hashes: Vec<B256>,
}

impl Rec {
    /// A record's named JSON (`c` of a `commit` job).
    pub fn of(c: &Value) -> Self {
        let hashes = |k: &str| arr(&c[k]).iter().filter_map(b32).collect();
        Rec {
            cts: num(&c["ctCount"]).unwrap_or(0) as usize,
            list_hash: b32(&c["ctListHash"]).unwrap_or_default(),
            key_hashes: hashes("nodeKeyHashes"),
            wrap_hashes: hashes("wrapHashes"),
        }
    }
}

/// A piece job on its own (`addPathList`, `addPathKeys`, `addPath`, a tree commit's `addWraps`), against its stored record,
/// the stored list's `ct_hashes` and what is in state at the head: every piece it holds hashes to its signed hash (node keys
/// admitted), and with it nothing the record signs is missing. `Ok(None)` relays it, `Ok(Some(reason))` waits for the missing
/// pieces, `Err` refuses it.
pub fn piece(
    entry: &str,
    args: &Value,
    r: &Rec,
    ct_hashes: &[B256],
    latest: &Landed,
) -> Result<Option<String>, String> {
    let bad = |what: String| Err(format!("{TREE_SET_REFUSED}: {what}; nothing sent"));
    let mut have = latest.clone();
    have.cts.resize(r.cts, false);
    have.wraps.resize(r.wrap_hashes.len(), false);
    match entry {
        "addPathList" => {
            if list_hash(&args["ctTargets"], &args["ctHashes"]) != Some(r.list_hash) {
                return bad("the list does not hash to ctListHash".into());
            }
            have.list = true;
        }
        "addPathKeys" => {
            let held = arr(&args["nodeKeys"]);
            for (k, (nk, h)) in held.iter().zip(&r.key_hashes).enumerate() {
                let pk = nk
                    .as_str()
                    .and_then(|s| alloy::hex::decode(s).ok())
                    .unwrap_or_default();
                if keccak256(&pk) != *h || !admissible(&pk) {
                    return bad(format!(
                        "node key {k}: not its signed hash or not admissible"
                    ));
                }
            }
            have.keys = held.len() == r.key_hashes.len();
        }
        "addPath" => {
            let first = num(&args["firstCt"]).unwrap_or(u64::MAX) as usize;
            for (j, ct) in arr(&args["cts"]).iter().enumerate() {
                let i = first.saturating_add(j);
                if ct_hashes
                    .get(i)
                    .is_none_or(|h| hash("PathCt", ct) != Some(*h))
                {
                    return bad(format!(
                        "ciphertext {i} does not hash to the stored list's ctHashes[{i}]"
                    ));
                }
                if let Some(x) = have.cts.get_mut(i) {
                    *x = true;
                }
            }
        }
        _ => {
            let first = num(&args["first"]).unwrap_or(u64::MAX) as usize;
            for (j, w) in arr(&args["wraps"]).iter().enumerate() {
                let i = first.saturating_add(j);
                if r.wrap_hashes
                    .get(i)
                    .is_none_or(|h| hash("Wrap", w) != Some(*h))
                {
                    return bad(format!("Welcome wrap {i} does not hash to wrapHashes[{i}]"));
                }
                if let Some(x) = have.wraps.get_mut(i) {
                    *x = true;
                }
            }
        }
    }
    let mut missing = Vec::new();
    if r.cts > 0 && !have.list {
        missing.push("the list".to_string());
    }
    if !r.key_hashes.is_empty() && !have.keys {
        missing.push("the node keys".into());
    }
    let n = have.cts.iter().filter(|x| !**x).count();
    if n > 0 {
        missing.push(format!("{n} ciphertext(s)"));
    }
    let n = have.wraps.iter().filter(|x| !**x).count();
    if n > 0 {
        missing.push(format!("{n} Welcome wrap(s)"));
    }
    Ok((!missing.is_empty()).then(|| {
        format!(
            "{TREE_SET_WAITING}: with this piece the record still misses {} in state; nothing sent",
            missing.join(", ")
        )
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(name: &str) -> Value {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../smartcontracts/vectors/pqchat")
            .join(name);
        serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
    }

    /// Numbers as the decimal strings a job carries.
    fn strings(v: &Value) -> Value {
        match v {
            Value::Number(n) => json!(n.to_string()),
            Value::Array(a) => Value::Array(a.iter().map(strings).collect()),
            Value::Object(o) => {
                Value::Object(o.iter().map(|(k, x)| (k.clone(), strings(x))).collect())
            }
            x => x.clone(),
        }
    }

    /// Every commit step of `tree-secrets.json`'s scenarios as a `commit` job's args (the signature a placeholder).
    fn sets() -> Vec<Value> {
        let v = rows("tree-secrets.json");
        let mut out = Vec::new();
        for sc in arr(&v["scenarios"]) {
            for st in arr(&sc["steps"]) {
                if st["record"]["ctCount"].is_null() {
                    continue;
                }
                out.push(json!({"c": strings(&st["record"]), "ctTargets": strings(&st["ctTargets"]),
                    "ctHashes": st["ctHashes"], "nodeKeys": st["nodeKeys"], "cts": st["cts"], "wraps": strings(&st["wraps"]),
                    "sig": {"keyData": "0x01", "signature": "0x02", "members": []}, "epochId": st["epochId"]}));
            }
        }
        out
    }

    /// The admission check equals the contract's, clientkeys' and `ua-rs`'s on `tree.json`'s `admission` rows.
    #[test]
    fn admission_is_the_vectors() {
        let v = rows("tree.json");
        let key = |r: &Value| alloy::hex::decode(r["kemPk"].as_str().unwrap()).unwrap();
        let (acc, refd) = (
            arr(&v["admission"]["accepted"]),
            arr(&v["admission"]["refused"]),
        );
        assert!(acc.len() >= 3 && refd.len() >= 10);
        for r in acc {
            assert!(admissible(&key(r)), "{}", r["name"]);
        }
        for r in refd {
            assert!(!admissible(&key(r)), "{}", r["name"]);
        }
    }

    /// Every scenario commit is a whole set (positive control) whose epoch id is the vectors'; one bad `ctHashes` entry, a
    /// node key that fails the admission check under its own signed hash, a missing piece of each kind and a wrong Welcome
    /// wrap are each refused by name (plan T4's test).
    #[test]
    fn the_whole_set_guard() {
        let all = sets();
        assert!(all.len() >= 20, "{}", all.len());
        let mut with_wraps = 0;
        for a in &all {
            let s = whole(a).unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(format!("{:#x}", s.eid), a["epochId"].as_str().unwrap());
            with_wraps += usize::from(s.adds > 0);
        }
        assert!(with_wraps > 0, "a scenario commit with Adds");
        let a = all
            .iter()
            .find(|a| arr(&a["cts"]).len() > 1 && !arr(&a["wraps"]).is_empty())
            .unwrap_or(&all[0]);
        let refused = |m: &dyn Fn(&mut Value), what: &str| {
            let mut b = a.clone();
            m(&mut b);
            let e = whole(&b).unwrap_err();
            assert!(
                e.starts_with(TREE_SET_REFUSED) && e.contains(what),
                "{what}: {e}"
            );
        };
        refused(
            &|b| b["ctHashes"][0] = json!(format!("{:#x}", B256::repeat_byte(7))),
            "the list does not hash",
        );
        refused(
            &|b| b["cts"][1]["x25519Eph"] = json!(format!("{:#x}", B256::repeat_byte(7))),
            "ciphertext 1",
        );
        refused(
            &|b| {
                b["cts"].as_array_mut().unwrap().pop();
            },
            "path ciphertexts",
        );
        refused(
            &|b| {
                b["nodeKeys"].as_array_mut().unwrap().pop();
            },
            "node keys",
        );
        refused(
            &|b| {
                b["ctTargets"] = json!([]);
                b["ctHashes"] = json!([]);
            },
            "the list",
        );
        if !arr(&a["wraps"]).is_empty() {
            refused(
                &|b| {
                    b["wraps"].as_array_mut().unwrap().pop();
                },
                "Welcome wraps",
            );
            refused(
                &|b| b["wraps"][0]["x25519Eph"] = json!(format!("{:#x}", B256::repeat_byte(7))),
                "Welcome wrap 0",
            );
        }
        // a node key that fails the admission check, signed under its own hash (the record's hash moved with it)
        let mut b = a.clone();
        let bad = format!("0x02{}", &a["nodeKeys"][0].as_str().unwrap()[4..]);
        b["c"]["nodeKeyHashes"][0] = json!(format!(
            "{:#x}",
            keccak256(alloy::hex::decode(&bad).unwrap())
        ));
        b["nodeKeys"][0] = json!(bad);
        let e = whole(&b).unwrap_err();
        assert!(e.contains("node key 0 fails the admission check"), "{e}");
    }

    fn set_of(cts: usize, keys: usize, adds: usize) -> Set {
        let ct = json!({"mlkemCt": "0x", "x25519Eph": "0x", "sealedSecret": "0x"});
        let w = json!({"member": "0x"});
        Set {
            eid: B256::repeat_byte(1),
            args: json!({"c": {}, "ctTargets": vec![json!("1"); cts], "ctHashes": vec![json!("0x"); cts],
                "nodeKeys": vec![json!("0x"); keys], "cts": vec![ct; cts], "wraps": vec![w; adds], "sig": {}}),
            cts,
            keys,
            adds,
        }
    }

    /// C37 walked to the end: each step's parts landed and made final in turn; the record, the list and the node keys go
    /// one by one; the held ciphertext goes last and alone (the job's own transaction), after every other piece is final; a
    /// part landed but not final is never sent again (plan T4: "the last transaction of a relayed commit holds one
    /// ciphertext"; mutant: the node keys sent last).
    #[test]
    fn c37_order_to_the_end() {
        for (cts, keys, adds) in [(5, 3, 2), (1, 1, 0), (0, 0, 3), (4, 2, 0)] {
            let s = set_of(cts, keys, adds);
            let mut latest = Landed {
                cts: vec![false; cts],
                wraps: vec![false; adds],
                ..Landed::default()
            };
            let mut fin = latest.clone();
            let mut order: Vec<&str> = Vec::new();
            let mut last = None;
            for _ in 0..20 {
                match step(&s, &latest, &fin) {
                    Step::Whole => {
                        order.push("commit");
                        latest.record = true;
                    }
                    Step::Parts(ps) => {
                        for (e, a) in ps {
                            order.push(e);
                            let first =
                                num(&a["firstCt"]).or(num(&a["first"])).unwrap_or(0) as usize;
                            match e {
                                "addPathList" => latest.list = true,
                                "addPathKeys" => latest.keys = true,
                                "addPath" => (first..first + arr(&a["cts"]).len())
                                    .for_each(|i| latest.cts[i] = true),
                                _ => (first..first + arr(&a["wraps"]).len())
                                    .for_each(|i| latest.wraps[i] = true),
                            }
                        }
                        // the same state again before finality sends nothing
                        assert!(
                            matches!(step(&s, &latest, &fin), Step::Wait(_)),
                            "{order:?}"
                        );
                    }
                    Step::Wait(_) => fin = latest.clone(),
                    Step::Last(e, a) => {
                        let n = arr(&a["cts"]).len() + arr(&a["wraps"]).len();
                        assert_eq!(n, 1, "the held piece alone");
                        assert_eq!(fin, latest, "every other piece final first");
                        last = Some(e);
                        order.push(e);
                        let first = num(&a["firstCt"]).or(num(&a["first"])).unwrap() as usize;
                        if e == "addPath" {
                            latest.cts[first] = true
                        } else {
                            latest.wraps[first] = true
                        }
                        fin = latest.clone();
                    }
                    Step::Done => break,
                }
            }
            assert_eq!(step(&s, &latest, &fin), Step::Done);
            assert_eq!(
                last,
                Some(if cts > 0 { "addPath" } else { "addWraps" }),
                "{order:?}"
            );
            // the record, then the list, then the node keys, each before anything after it
            let pos = |e: &str| order.iter().position(|x| *x == e);
            if cts > 0 {
                assert!(
                    pos("commit") < pos("addPathList") && pos("addPathList") < pos("addPathKeys"),
                    "{order:?}"
                );
                assert!(pos("addPathKeys") < pos("addPath"), "{order:?}");
            }
            assert_eq!(order.last(), Some(&last.unwrap()), "{order:?}");
        }
    }

    /// A piece job on its own: relayed only when it completes the record; a wrong hash refused; a missing piece waits.
    #[test]
    fn a_piece_alone() {
        let a = sets()
            .into_iter()
            .find(|a| arr(&a["cts"]).len() > 1)
            .unwrap();
        let s = whole(&a).unwrap();
        let mut latest = Landed::all(&s);
        let last = s.cts - 1;
        latest.cts[last] = false;
        let (r, list): (Rec, Vec<B256>) = (
            Rec::of(&a["c"]),
            arr(&a["ctHashes"]).iter().filter_map(b32).collect(),
        );
        let job = json!({"epochId": "0x", "firstCt": last.to_string(), "cts": [a["cts"][last]]});
        assert_eq!(piece("addPath", &job, &r, &list, &latest), Ok(None));
        latest.cts[0] = false;
        let w = piece("addPath", &job, &r, &list, &latest).unwrap().unwrap();
        assert!(
            w.starts_with(TREE_SET_WAITING) && w.contains("1 ciphertext"),
            "{w}"
        );
        let bad = json!({"epochId": "0x", "firstCt": "0", "cts": [a["cts"][last]]});
        assert!(piece("addPath", &bad, &r, &list, &latest)
            .unwrap_err()
            .starts_with(TREE_SET_REFUSED));
    }

    #[test]
    fn halves() {
        let (lo, hi) = halve(
            "addPath",
            &json!({"epochId": "0x", "firstCt": "4", "cts": [1, 2, 3]}),
        )
        .unwrap();
        assert_eq!(
            (lo["firstCt"].clone(), lo["cts"].clone()),
            (json!("4"), json!([1]))
        );
        assert_eq!(
            (hi["firstCt"].clone(), hi["cts"].clone()),
            (json!("5"), json!([2, 3]))
        );
        assert!(halve("addPath", &json!({"firstCt": "4", "cts": [1]})).is_none());
    }
}
