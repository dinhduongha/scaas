// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! scaas-sdk T8a–T8g (spec §23.1 item 6): the named entries, one test per domain kind. Every `(struct, kind)` pair of
//! `smartcontracts/vectors/typed/typed_ops.json` builds the row's `calldata` and the job `op` the node's own test makes of
//! that row (`scaas-node/src/typed.rs` `testkit::op_of`, which the node's `typed_ops_kat_every_entry` parses back to the same
//! calldata); and the table is the node's, both ways: this test reads `scaas-node/src/typed.rs` (`TYPED`, `NESTED`, the kind
//! constants, the plans, `NO_NODE_ROW`) and every node row of the kind has a row here, every row here a node row (the release
//! approvals excepted, by the node's own list). UNAUDITED.
use scaas_ua::wallet::entries::{entry, entry_rows, EntryRow, entry_structs, init_hash, relay_fee_op, relay_fee_router_calldata, relay_ref};
use scaas_ua::wallet::Error;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

fn root(p: &str) -> String {
    format!("{}/../../{p}", env!("CARGO_MANIFEST_DIR"))
}
fn load(p: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(root(p)).unwrap()).unwrap()
}
fn ops() -> Value {
    load("smartcontracts/vectors/typed/typed_ops.json")
}
fn b20(v: &Value) -> [u8; 20] {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap().try_into().unwrap()
}
fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}

// --- the node's table, read from its source ---

/// The top-level tuples of a Rust slice literal: each element a quoted string or an identifier.
fn tuples(block: &str) -> Vec<Vec<String>> {
    let text: String = block.lines().filter(|l| !l.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n");
    let (mut out, mut cur, mut item, mut depth, mut quoted) = (vec![], vec![], String::new(), 0, false);
    for c in text.chars() {
        match (quoted, c) {
            (true, '"') => quoted = false,
            (true, _) => item.push(c),
            (false, '"') => quoted = true,
            (false, '(') => {
                depth += 1;
                if depth > 1 {
                    item.push(c);
                }
            }
            (false, ')') => {
                depth -= 1;
                if depth == 0 {
                    cur.push(std::mem::take(&mut item).trim().to_string());
                    out.push(std::mem::take(&mut cur));
                } else {
                    item.push(c);
                }
            }
            (false, ',') if depth == 1 => cur.push(std::mem::take(&mut item).trim().to_string()),
            (false, c) if depth >= 1 && !c.is_whitespace() => item.push(c),
            _ => {}
        }
    }
    out
}

struct Node {
    /// `(struct, kind)` → `(entry, fields expanded, plan resolved)`.
    rows: BTreeMap<(String, String), (String, String, String)>,
    nested: BTreeMap<String, String>,
    no_node_row: Vec<String>,
}

fn node() -> Node {
    let src = std::fs::read_to_string(root("scaas-node/src/typed.rs")).unwrap();
    let block = |head: &str| -> String {
        let i = src.find(head).unwrap_or_else(|| panic!("{head} in typed.rs"));
        let rest = &src[i + head.len()..];
        rest[..rest.find("\n];").unwrap()].to_string()
    };
    let konst = |name: &str| -> String {
        let head = format!("const {name}: &str = \"");
        let i = src.find(&head).unwrap_or_else(|| panic!("{name}"));
        let rest = &src[i + head.len()..];
        rest[..rest.find('"').unwrap()].to_string()
    };
    let kinds = |name: &str| -> Vec<String> {
        let head = format!("const {name}: &[&str] = &[");
        let i = src.find(&head).unwrap_or_else(|| panic!("kinds {name}"));
        let rest = &src[i + head.len()..];
        rest[..rest.find(']').unwrap()].split(',').map(|s| s.trim().trim_matches('"').to_string()).collect()
    };
    let env = konst("E_FIELDS");
    let mut rows = BTreeMap::new();
    for t in tuples(&block("const TYPED: &[(&str, &str, &[&str], &str, &str)] = &[")) {
        let [name, entry, k, f, plan] = <[String; 5]>::try_from(t).unwrap();
        let fields = f.strip_suffix(",E").map_or(f.clone(), |h| format!("{h},{env}"));
        let plan = if plan.chars().all(|c| c.is_ascii_uppercase() || c == '_') && !plan.is_empty() { konst(&plan) } else { plan };
        for kind in kinds(&k) {
            assert!(rows.insert((name.clone(), kind), (entry.clone(), fields.clone(), plan.clone())).is_none(), "{name}");
        }
    }
    let nested = tuples(&block("const NESTED: &[(&str, &str)] = &[")).into_iter().map(|t| (t[0].clone(), t[1].clone())).collect();
    let i = src.find("pub const NO_NODE_ROW: [&str; ").unwrap();
    let rest = &src[i..];
    let list = &rest[rest.find("= [").unwrap() + 3..rest.find("];").unwrap()];
    let no_node_row = list.split(',').map(|s| s.trim().trim_matches('"').to_string()).filter(|s| !s.is_empty()).collect();
    Node { rows, nested, no_node_row }
}

/// Both ways on `kind`: every node row of the kind is a row here with the same entry, fields and plan; every node row here is
/// one of the node's; the rows here that the node lacks are the node's own `NO_NODE_ROW` (the release approvals).
fn table_both_ways(kind: &str) {
    let n = node();
    let mine: Vec<_> = entry_rows().into_iter().filter(|r| r.kinds.contains(&kind)).collect();
    let ours: BTreeMap<(String, String), (String, String, String)> = mine.iter().filter(|r| r.node)
        .map(|r| ((r.name.to_string(), kind.to_string()), (r.entry.to_string(), r.fields.clone(), r.plan.to_string()))).collect();
    let theirs: BTreeMap<_, _> = n.rows.iter().filter(|((_, k), _)| k == kind).map(|(a, b)| (a.clone(), b.clone())).collect();
    for (k, v) in &theirs {
        assert_eq!(ours.get(k), Some(v), "node row {k:?} has no equal row here");
    }
    for (k, v) in &ours {
        assert_eq!(theirs.get(k), Some(v), "row {k:?} here is no node row");
    }
    for r in mine.iter().filter(|r| !r.node) {
        assert!(n.no_node_row.contains(&r.name.to_string()), "{}: a row without a node row must be the node's NO_NODE_ROW", r.name);
        assert!(!n.rows.contains_key(&(r.name.to_string(), kind.to_string())), "{}: the node has it after all", r.name);
    }
    for (name, fields) in entry_structs() {
        assert_eq!(n.nested.get(*name).map(String::as_str), Some(*fields), "struct {name}: the node's NESTED");
    }
}

// --- the vector rows ---

fn sig_form(name: &str, kind: &str, plan: &str) -> &'static str {
    if plan.contains("@bytes") {
        "bytes"
    } else if plan.contains("@ua") || name.starts_with("UA") || name.starts_with("CancelUA") {
        "UASig"
    } else if kind == "account" {
        "AccountSig"
    } else {
        "bytes"
    }
}

fn sig_of(form: &str, s: &Value) -> Value {
    match form {
        "UASig" => json!({"keyData": "0x", "signature": s, "members": []}),
        "AccountSig" => json!({"keyIndex": "0", "proof": [], "signature": s}),
        _ => s.clone(),
    }
}

/// The vector row's unsigned arguments in the node's job forms (`testkit::split`): a `PayMeta` body named, `payerSig` a
/// `UASig`, a generic creation's `init_call`, a wrap order's `underlying` the domain's contract; the job's `validUntil`.
fn extra_of(name: &str, plan: &str, d: &Value) -> Map<String, Value> {
    let mut x = d.get("extra").and_then(Value::as_object).cloned().unwrap_or_default();
    if let Some(m) = x.get_mut("meta") {
        assert_eq!((m["schema"].as_u64(), m["body"].as_str()), (Some(0), Some("0x")), "{name}: a vector meta beyond schema 0");
        m.as_object_mut().unwrap().remove("body");
    }
    if let Some(s) = x.remove("payerSig") {
        x.insert("payerSig".into(), sig_of("UASig", &s));
    }
    if let Some(c) = x.remove("initCall") {
        x.insert("init_call".into(), c);
    }
    if plan.contains("underlying:address") {
        x.insert("underlying".into(), d["domain"]["verifyingContract"].clone());
    }
    x.insert("validUntil".into(), json!("1800000300"));
    x
}

/// What the node's `testkit::op_of` makes of the row.
fn op_of(r: &EntryRow, kind: &str, msg: &Value, x: &Map<String, Value>, d: &Value) -> Value {
    let (name, entry_name, fields, plan) = (r.name, r.entry, r.fields.as_str(), r.plan);
    let env_keys = ["from", "batch", "nonce", "validUntil", "mode", "relayer", "fee", "feeRecipient"];
    let enveloped = fields.ends_with("uint256 fee,address feeRecipient");
    let mut args = msg.as_object().unwrap().clone();
    let mut env = Map::new();
    if enveloped {
        for k in env_keys {
            env.insert(k.into(), args.remove(k).unwrap());
        }
    }
    args.extend(x.iter().filter(|(k, _)| !matches!(k.as_str(), "pqzVerdict" | "validUntil")).map(|(k, v)| (k.clone(), v.clone())));
    if plan.contains("initcall!") {
        args.remove("initHash");
    }
    let form = sig_form(name, kind, plan);
    let mut op = json!({"entry": entry_name, "contract": kind, "struct": name, "token": d["domain"]["verifyingContract"],
        "args": args, "validUntil": "1800000300"});
    if enveloped {
        op["envelope"] = Value::Object(env);
    }
    op[if form == "bytes" { "signature" } else { "auth" }] = sig_of(form, &d["signature"]);
    op
}

/// Numbers as decimal strings, hex lowercase: the forms the node takes as equal.
fn norm(v: &Value) -> Value {
    match v {
        Value::Number(n) => json!(n.to_string()),
        Value::String(s) if s.starts_with("0x") => json!(s.to_ascii_lowercase()),
        Value::Array(a) => Value::Array(a.iter().map(norm).collect()),
        Value::Object(o) => Value::Object(o.iter().map(|(k, v)| (k.clone(), norm(v))).collect()),
        other => other.clone(),
    }
}

/// Every pair of `kind` in the vector file: the calldata and the job op; returns the pairs walked.
fn vector_pairs(kind: &str) -> usize {
    let v = ops();
    let rows = entry_rows();
    let mut walked = 0;
    for (name, o) in v["ops"].as_object().unwrap() {
        let Some(d) = o["domains"].get(kind) else { continue };
        if name == "PqzAuth" {
            assert!(d.get("calldata").is_none(), "PqzAuth has no entry of its own");
            continue;
        }
        let r = rows.iter().find(|r| r.name == name && r.kinds.contains(&kind)).unwrap_or_else(|| panic!("{name} on {kind}: no builder"));
        if matches!(name.as_str(), "UACreateToken" | "UACreateDex") {
            creation(name, kind, o, d);
            walked += 1;
            continue;
        }
        let x = extra_of(name, r.plan, d);
        let form = sig_form(name, kind, r.plan);
        let sig = sig_of(form, &d["signature"]);
        let contract = b20(&d["domain"]["verifyingContract"]);
        let b = entry(name, kind, &contract, &o["message"], &Value::Object(x.clone()), &sig)
            .unwrap_or_else(|e| panic!("{name} on {kind}: {e:?}"));
        assert_eq!(hex::encode(&b.calldata), d["calldata"].as_str().unwrap()[2..], "{name} on {kind}: {}", d["abi"]);
        assert_eq!(norm(&b.message), norm(&o["message"]), "{name} on {kind}: the canonical message");
        match &b.op {
            Some(op) => {
                let want = op_of(r, kind, &o["message"], &x, d);
                if name == "UARelayFee" {
                    relay_fee(kind, o, d, &sig);
                } else {
                    assert_eq!(norm(op), norm(&want), "{name} on {kind}: the job op");
                }
            }
            None => assert!(!r.node, "{name}: a node row builds its op"),
        }
        walked += 1;
    }
    walked
}

/// The router extras of a `UARelayFee` row: `relayRef`, the lane, the router's `relay` calldata; and its job op with a call.
fn relay_fee(kind: &str, o: &Value, d: &Value, sig: &Value) {
    let m = &o["message"];
    let call = bytes(&d["relayedCall"]);
    let chain_id: u64 = d["domain"]["chainId"].as_str().unwrap().parse().unwrap();
    assert_eq!(hex::encode(relay_ref(chain_id, &b20(&m["target"]), &call)), d["relayRef"].as_str().unwrap()[2..], "{kind}: relayRef");
    assert_eq!(m["batch"], d["lane"], "{kind}: the lane is the payer's batch");
    let token = b20(&d["domain"]["verifyingContract"]);
    let rc = relay_fee_router_calldata(m, &token, &call, sig).unwrap();
    assert_eq!(hex::encode(rc), d["routerCalldata"].as_str().unwrap()[2..], "{kind}: routerCalldata");
    let mut wrong = call.clone();
    wrong[0] ^= 1;
    assert_eq!(relay_fee_router_calldata(m, &token, &wrong, sig), Err(Error::Argument), "{kind}: a call that is not the signed hash");
    // the job: a call whose calldata is the signed hash and whose target is the signed target joins; anything else is refused
    let v = ops();
    let burn = &v["ops"]["UABurn"];
    let bd = &burn["domains"][kind];
    let bsig = sig_of("UASig", &bd["signature"]);
    let mut bmsg = burn["message"].clone();
    let inner = entry("UABurn", kind, &b20(&m["target"]), &bmsg, &json!({}), &bsig).unwrap();
    let mut fee_msg = m.clone();
    fee_msg["callDataHash"] = json!(format!("0x{}", hex::encode(scaas_ua::keccak256(&inner.calldata))));
    let fee = entry("UARelayFee", kind, &token, &fee_msg, &json!({}), sig).unwrap();
    let op = relay_fee_op(&fee, &inner).unwrap();
    assert_eq!(op["call"], inner.op.clone().unwrap());
    assert!(op["args"].get("target").is_none() && op["args"].get("callDataHash").is_none(), "{op}");
    bmsg["amount"] = json!("1");
    let other = entry("UABurn", kind, &b20(&m["target"]), &bmsg, &json!({}), &bsig).unwrap();
    assert_eq!(relay_fee_op(&fee, &other), Err(Error::Argument), "{kind}: a call that is not the signed hash");
    let elsewhere = entry("UABurn", kind, &token, &burn["message"], &json!({}), &bsig).unwrap();
    assert_eq!(relay_fee_op(&fee, &elsewhere), Err(Error::Argument), "{kind}: a call on another target");
    assert_eq!(relay_fee_op(&fee, &fee), Err(Error::Argument), "{kind}: a relay fee as the call");
}

/// `UACreateToken` / `UACreateDex` (owner 2026-11-12): the config is named JSON; its `abi.encode` is the init argument and its
/// keccak the signed `initHash` (`vectors/factory/create_config.json`, checked by forge field by field). The vector row's
/// `initArgs` is a filler, so its calldata is checked by selector and by the signed digest's other fields.
fn creation(name: &str, kind: &str, o: &Value, d: &Value) {
    let kat = load("smartcontracts/vectors/factory/create_config.json");
    let k = if name == "UACreateToken" { "token" } else { "dex" };
    let x = json!({"config": kat[k]["config"], "validUntil": "1800000300"});
    let h = init_hash(name, kind, &x).unwrap().unwrap();
    assert_eq!(format!("0x{}", hex::encode(h)), kat[k]["initHash"].as_str().unwrap(), "{name}: initHash = keccak256(abi.encode(config))");
    let mut msg = o["message"].clone();
    msg.as_object_mut().unwrap().remove("initHash");
    let sig = sig_of("UASig", &d["signature"]);
    let b = entry(name, kind, &b20(&d["domain"]["verifyingContract"]), &msg, &x, &sig).unwrap();
    assert_eq!(hex::encode(&b.calldata[..4]), d["selector"].as_str().unwrap()[2..], "{name}: {}", d["abi"]);
    let init = bytes(&kat[k]["initArgs"]);
    assert!(b.calldata.windows(init.len()).any(|w| w == init), "{name}: the init argument is abi.encode(config)");
    assert_eq!(b.message["initHash"], kat[k]["initHash"], "{name}: the signed initHash");
    let op = b.op.unwrap();
    assert!(op["args"].get("initHash").is_none(), "{name}: the node hashes the config");
    assert_eq!(norm(&op["args"]["config"]), norm(&kat[k]["config"]), "{name}: the config by name");
    // a supplied initHash must be the config's
    msg["initHash"] = json!(format!("0x{}", "11".repeat(32)));
    assert_eq!(entry(name, kind, &b20(&d["domain"]["verifyingContract"]), &msg, &x, &sig), Err(Error::Argument), "{name}: initHash");
}

/// `MetaTxLib.canon` with a non-zero unbound value: every row with a fee mode, at mode 0 (`relayer` and `feeRecipient` both
/// unbound), builds the same calldata, op and message with them set as with them 0, and both are 0 in what it sends; the
/// control: a bound relayer named moves the calldata.
fn canon_unbound(kind: &str) {
    let v = ops();
    let rows = entry_rows();
    let mut checked = 0;
    let at_mode = |m: &Value, mode: u64, who: &str| -> Value {
        let mut m = m.clone();
        let t = if m.get("payment").is_some() { &mut m["payment"] } else { &mut m };
        t["mode"] = json!(mode);
        t["relayer"] = json!(who);
        t["feeRecipient"] = json!(who);
        m
    };
    for (name, o) in v["ops"].as_object().unwrap() {
        let Some(d) = o["domains"].get(kind) else { continue };
        let m = &o["message"];
        let has_mode = m.get("feeRecipient").or_else(|| m.get("payment").and_then(|p| p.get("feeRecipient"))).is_some();
        if d.get("calldata").is_none() || !has_mode || matches!(name.as_str(), "UACreateToken" | "UACreateDex") {
            continue;
        }
        let r = rows.iter().find(|r| r.name == name && r.kinds.contains(&kind)).unwrap();
        let x = Value::Object(extra_of(name, r.plan, d));
        let sig = sig_of(sig_form(name, kind, r.plan), &d["signature"]);
        let at = b20(&d["domain"]["verifyingContract"]);
        let zero = "0x0000000000000000000000000000000000000000";
        let beef = "0x00000000000000000000000000000000deadbeef";
        let base = entry(name, kind, &at, &at_mode(m, 0, zero), &x, &sig).unwrap();
        let b = entry(name, kind, &at, &at_mode(m, 0, beef), &x, &sig).unwrap();
        assert_eq!((&b.calldata, &b.op, &b.message), (&base.calldata, &base.op, &base.message), "{name} on {kind}: unbound zeroed");
        assert!(!hex::encode(&b.calldata).contains("deadbeef"), "{name} on {kind}: an unbound value sent");
        // control: mode 3 binds both: the named relayer is sent
        let c = entry(name, kind, &at, &at_mode(m, 3, beef), &x, &sig).unwrap();
        assert!(hex::encode(&c.calldata).contains("deadbeef"), "{name} on {kind}: a bound relayer is sent");
        checked += 1;
    }
    assert!(checked > 0, "{kind}: no row with a fee mode");
}

/// Refusals by name, each with its control: an unknown field, a missing one, an unknown extra, a wrong signature form.
fn refusals(kind: &str, name: &str) {
    let v = ops();
    let o = &v["ops"][name];
    let d = &o["domains"][kind];
    let r = entry_rows().into_iter().find(|r| r.name == name && r.kinds.contains(&kind)).unwrap();
    let x = Value::Object(extra_of(name, r.plan, d));
    let form = sig_form(name, kind, r.plan);
    let sig = sig_of(form, &d["signature"]);
    let at = b20(&d["domain"]["verifyingContract"]);
    assert!(entry(name, kind, &at, &o["message"], &x, &sig).is_ok(), "control");
    let mut m = o["message"].clone();
    m["data"] = json!("0x00");
    assert_eq!(entry(name, kind, &at, &m, &x, &sig), Err(Error::Argument), "{name}: an unknown field");
    let mut m = o["message"].clone();
    let first = m.as_object().unwrap().keys().next().unwrap().clone();
    m.as_object_mut().unwrap().remove(&first);
    assert_eq!(entry(name, kind, &at, &m, &x, &sig), Err(Error::Argument), "{name}: {first} missing");
    let mut y = x.clone();
    y["calldata"] = json!("0x00");
    assert_eq!(entry(name, kind, &at, &o["message"], &y, &sig), Err(Error::Argument), "{name}: an unknown extra");
    let wrong = if form == "bytes" { sig_of("UASig", &d["signature"]) } else { d["signature"].clone() };
    assert_eq!(entry(name, kind, &at, &o["message"], &x, &wrong), Err(Error::Argument), "{name}: the other signature form");
    assert_eq!(entry(name, "nope", &at, &o["message"], &x, &sig), Err(Error::Argument), "{name}: no such kind");
}

#[test]
fn entries_token() {
    table_both_ways("token");
    assert_eq!(vector_pairs("token"), 15, "every token pair of typed_ops.json");
    canon_unbound("token");
    refusals("token", "UAUnwrap");
    refusals("token", "Wrap");
    // two node rows with no row of typed_ops.json (`mtxPay`, the token's `mtxInvalidateNonces`): held to the node's table above
    let rows: BTreeSet<_> = entry_rows().into_iter().filter(|r| r.kinds.contains(&"token")).map(|r| r.name).collect();
    assert!(rows.contains("UAMetaTransfer") && rows.contains("UAInvalidateNonces"));
}

#[test]
fn entries_zether() {
    table_both_ways("zether");
    assert_eq!(vector_pairs("zether"), 28, "every zether pair of typed_ops.json");
    canon_unbound("zether");
    refusals("zether", "UAZetherTransfer");
    refusals("zether", "ZetherRollOver");
}
