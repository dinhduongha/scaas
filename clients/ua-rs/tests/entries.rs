// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! scaas-sdk T8a–T8g (spec §23.1 item 6): the named entries, one test per domain kind. Every `(struct, kind)` pair of
//! `smartcontracts/vectors/typed/typed_ops.json` builds the row's `calldata` and the job `op` the node's own test makes of
//! that row (`scaas-node/src/typed.rs` `testkit::op_of`, which the node's `typed_ops_kat_every_entry` parses back to the same
//! calldata); and the table is the node's, both ways: this test reads `scaas-node/src/typed.rs` (`TYPED`, `NESTED`, the kind
//! constants, the plans, `NO_NODE_ROW`) and every node row of the kind has a row here, every row here a node row (the release
//! approvals excepted, by the node's own list). UNAUDITED.
use scaas_ua::wallet::entries::{
    entry, entry_rows, entry_structs, init_hash, pay_meta_of, relay_fee_op,
    relay_fee_router_calldata, relay_ref, transfer_on_ids, EntryRow,
};
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
    hex::decode(v.as_str().unwrap().trim_start_matches("0x"))
        .unwrap()
        .try_into()
        .unwrap()
}
fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}

// --- the node's table, read from its source ---

/// The top-level tuples of a Rust slice literal: each element a quoted string or an identifier.
fn tuples(block: &str) -> Vec<Vec<String>> {
    let text: String = block
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    let (mut out, mut cur, mut item, mut depth, mut quoted) =
        (vec![], vec![], String::new(), 0, false);
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
        let i = src
            .find(head)
            .unwrap_or_else(|| panic!("{head} in typed.rs"));
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
        rest[..rest.find(']').unwrap()]
            .split(',')
            .map(|s| s.trim().trim_matches('"').to_string())
            .collect()
    };
    let env = konst("E_FIELDS");
    let mut rows = BTreeMap::new();
    for t in tuples(&block(
        "const TYPED: &[(&str, &str, &[&str], &str, &str)] = &[",
    )) {
        let [name, entry, k, f, plan] = <[String; 5]>::try_from(t).unwrap();
        let fields = f
            .strip_suffix(",E")
            .map_or(f.clone(), |h| format!("{h},{env}"));
        let plan = if plan.chars().all(|c| c.is_ascii_uppercase() || c == '_') && !plan.is_empty() {
            konst(&plan)
        } else {
            plan
        };
        for kind in kinds(&k) {
            assert!(
                rows.insert(
                    (name.clone(), kind),
                    (entry.clone(), fields.clone(), plan.clone())
                )
                .is_none(),
                "{name}"
            );
        }
    }
    let nested = tuples(&block("const NESTED: &[(&str, &str)] = &["))
        .into_iter()
        .map(|t| (t[0].clone(), t[1].clone()))
        .collect();
    let i = src.find("pub const NO_NODE_ROW: [&str; ").unwrap();
    let rest = &src[i..];
    let list = &rest[rest.find("= [").unwrap() + 3..rest.find("];").unwrap()];
    let no_node_row = list
        .split(',')
        .map(|s| s.trim().trim_matches('"').to_string())
        .filter(|s| !s.is_empty())
        .collect();
    Node {
        rows,
        nested,
        no_node_row,
    }
}

/// Both ways on `kind`: every node row of the kind is a row here with the same entry, fields and plan; every node row here is
/// one of the node's; the rows here that the node lacks are the node's own `NO_NODE_ROW` (the release approvals).
fn table_both_ways(kind: &str) {
    let n = node();
    let mine: Vec<_> = entry_rows()
        .into_iter()
        .filter(|r| r.kinds.contains(&kind))
        .collect();
    let ours: BTreeMap<(String, String), (String, String, String)> = mine
        .iter()
        .filter(|r| r.node)
        .map(|r| {
            (
                (r.name.to_string(), kind.to_string()),
                (r.entry.to_string(), r.fields.clone(), r.plan.to_string()),
            )
        })
        .collect();
    let theirs: BTreeMap<_, _> = n
        .rows
        .iter()
        .filter(|((_, k), _)| k == kind)
        .map(|(a, b)| (a.clone(), b.clone()))
        .collect();
    for (k, v) in &theirs {
        assert_eq!(ours.get(k), Some(v), "node row {k:?} has no equal row here");
    }
    for (k, v) in &ours {
        assert_eq!(theirs.get(k), Some(v), "row {k:?} here is no node row");
    }
    for r in mine.iter().filter(|r| !r.node) {
        assert!(
            n.no_node_row.contains(&r.name.to_string()),
            "{}: a row without a node row must be the node's NO_NODE_ROW",
            r.name
        );
        assert!(
            !n.rows.contains_key(&(r.name.to_string(), kind.to_string())),
            "{}: the node has it after all",
            r.name
        );
    }
    for (name, fields) in entry_structs() {
        assert_eq!(
            n.nested.get(*name).map(String::as_str),
            Some(*fields),
            "struct {name}: the node's NESTED"
        );
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
    let mut x = d
        .get("extra")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    if let Some(m) = x.get_mut("meta") {
        assert_eq!(
            (m["schema"].as_u64(), m["body"].as_str()),
            (Some(0), Some("0x")),
            "{name}: a vector meta beyond schema 0"
        );
        m.as_object_mut().unwrap().remove("body");
    }
    if let Some(s) = x.remove("payerSig") {
        x.insert("payerSig".into(), sig_of("UASig", &s));
    }
    if let Some(c) = x.remove("initCall") {
        x.insert("init_call".into(), c);
    }
    if plan.contains("underlying:address") {
        x.insert(
            "underlying".into(),
            d["domain"]["verifyingContract"].clone(),
        );
    }
    x.insert("validUntil".into(), json!("1800000300"));
    x
}

/// What the node's `testkit::op_of` makes of the row.
fn op_of(r: &EntryRow, kind: &str, msg: &Value, x: &Map<String, Value>, d: &Value) -> Value {
    let (name, entry_name, fields, plan) = (r.name, r.entry, r.fields.as_str(), r.plan);
    let env_keys = [
        "from",
        "batch",
        "nonce",
        "validUntil",
        "mode",
        "relayer",
        "fee",
        "feeRecipient",
    ];
    let enveloped = fields.ends_with("uint256 fee,address feeRecipient");
    let mut args = msg.as_object().unwrap().clone();
    let mut env = Map::new();
    if enveloped {
        for k in env_keys {
            env.insert(k.into(), args.remove(k).unwrap());
        }
    }
    args.extend(
        x.iter()
            .filter(|(k, _)| !matches!(k.as_str(), "pqzVerdict" | "validUntil"))
            .map(|(k, v)| (k.clone(), v.clone())),
    );
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
        let Some(d) = o["domains"].get(kind) else {
            continue;
        };
        // no entry of their own: `PqzAuth` (attached by the PQZ facade), `AuditorConsent` (set-auditor, relayed beside the op)
        if matches!(name.as_str(), "PqzAuth" | "AuditorConsent") {
            assert!(
                d.get("calldata").is_none(),
                "{name} has no entry of its own"
            );
            continue;
        }
        let r = rows
            .iter()
            .find(|r| r.name == name && r.kinds.contains(&kind))
            .unwrap_or_else(|| panic!("{name} on {kind}: no builder"));
        if matches!(name.as_str(), "UACreateToken" | "UACreateDex") {
            creation(name, kind, o, d);
            walked += 1;
            continue;
        }
        let x = extra_of(name, r.plan, d);
        let form = sig_form(name, kind, r.plan);
        let sig = sig_of(form, &d["signature"]);
        let contract = b20(&d["domain"]["verifyingContract"]);
        let b = entry(
            name,
            kind,
            &contract,
            &o["message"],
            &Value::Object(x.clone()),
            &sig,
        )
        .unwrap_or_else(|e| panic!("{name} on {kind}: {e:?}"));
        assert_eq!(
            hex::encode(&b.calldata),
            d["calldata"].as_str().unwrap()[2..],
            "{name} on {kind}: {}",
            d["abi"]
        );
        assert_eq!(
            norm(&b.message),
            norm(&o["message"]),
            "{name} on {kind}: the canonical message"
        );
        match &b.op {
            Some(op) => {
                assert!(r.node, "{name}: no node row, no job op");
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
    assert_eq!(
        hex::encode(relay_ref(chain_id, &b20(&m["target"]), &call)),
        d["relayRef"].as_str().unwrap()[2..],
        "{kind}: relayRef"
    );
    assert_eq!(
        m["batch"], d["lane"],
        "{kind}: the lane is the payer's batch"
    );
    let token = b20(&d["domain"]["verifyingContract"]);
    let rc = relay_fee_router_calldata(m, &token, &call, sig).unwrap();
    assert_eq!(
        hex::encode(rc),
        d["routerCalldata"].as_str().unwrap()[2..],
        "{kind}: routerCalldata"
    );
    let mut wrong = call.clone();
    wrong[0] ^= 1;
    assert_eq!(
        relay_fee_router_calldata(m, &token, &wrong, sig),
        Err(Error::Argument),
        "{kind}: a call that is not the signed hash"
    );
    // the job: a call whose calldata is the signed hash and whose target is the signed target joins; anything else is refused
    let v = ops();
    let burn = &v["ops"]["UABurn"];
    let bd = &burn["domains"][kind];
    let bsig = sig_of("UASig", &bd["signature"]);
    let mut bmsg = burn["message"].clone();
    let inner = entry("UABurn", kind, &b20(&m["target"]), &bmsg, &json!({}), &bsig).unwrap();
    let mut fee_msg = m.clone();
    fee_msg["callDataHash"] = json!(format!(
        "0x{}",
        hex::encode(scaas_ua::keccak256(&inner.calldata))
    ));
    let fee = entry("UARelayFee", kind, &token, &fee_msg, &json!({}), sig).unwrap();
    let op = relay_fee_op(&fee, &inner).unwrap();
    assert_eq!(op["call"], inner.op.clone().unwrap());
    assert!(
        op["args"].get("target").is_none() && op["args"].get("callDataHash").is_none(),
        "{op}"
    );
    bmsg["amount"] = json!("1");
    let other = entry("UABurn", kind, &b20(&m["target"]), &bmsg, &json!({}), &bsig).unwrap();
    assert_eq!(
        relay_fee_op(&fee, &other),
        Err(Error::Argument),
        "{kind}: a call that is not the signed hash"
    );
    let elsewhere = entry("UABurn", kind, &token, &burn["message"], &json!({}), &bsig).unwrap();
    assert_eq!(
        relay_fee_op(&fee, &elsewhere),
        Err(Error::Argument),
        "{kind}: a call on another target"
    );
    assert_eq!(
        relay_fee_op(&fee, &fee),
        Err(Error::Argument),
        "{kind}: a relay fee as the call"
    );
}

/// `UACreateToken` / `UACreateDex` (owner 2026-11-12): the config is named JSON; its `abi.encode` is the init argument and its
/// keccak the signed `initHash` (`vectors/factory/create_config.json`, checked by forge field by field). The vector row's
/// `initArgs` is a filler, so its calldata is checked by selector and by the signed digest's other fields.
fn creation(name: &str, kind: &str, o: &Value, d: &Value) {
    let kat = load("smartcontracts/vectors/factory/create_config.json");
    let k = if name == "UACreateToken" {
        "token"
    } else {
        "dex"
    };
    let x = json!({"config": kat[k]["config"], "validUntil": "1800000300"});
    let h = init_hash(name, kind, &x).unwrap().unwrap();
    assert_eq!(
        format!("0x{}", hex::encode(h)),
        kat[k]["initHash"].as_str().unwrap(),
        "{name}: initHash = keccak256(abi.encode(config))"
    );
    let mut msg = o["message"].clone();
    msg.as_object_mut().unwrap().remove("initHash");
    let sig = sig_of("UASig", &d["signature"]);
    let b = entry(
        name,
        kind,
        &b20(&d["domain"]["verifyingContract"]),
        &msg,
        &x,
        &sig,
    )
    .unwrap();
    assert_eq!(
        hex::encode(&b.calldata[..4]),
        d["selector"].as_str().unwrap()[2..],
        "{name}: {}",
        d["abi"]
    );
    let init = bytes(&kat[k]["initArgs"]);
    assert!(
        b.calldata.windows(init.len()).any(|w| w == init),
        "{name}: the init argument is abi.encode(config)"
    );
    assert_eq!(
        b.message["initHash"], kat[k]["initHash"],
        "{name}: the signed initHash"
    );
    let op = b.op.unwrap();
    assert!(
        op["args"].get("initHash").is_none(),
        "{name}: the node hashes the config"
    );
    assert_eq!(
        norm(&op["args"]["config"]),
        norm(&kat[k]["config"]),
        "{name}: the config by name"
    );
    // a supplied initHash must be the config's
    msg["initHash"] = json!(format!("0x{}", "11".repeat(32)));
    assert_eq!(
        entry(
            name,
            kind,
            &b20(&d["domain"]["verifyingContract"]),
            &msg,
            &x,
            &sig
        ),
        Err(Error::Argument),
        "{name}: initHash"
    );
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
        let t = if m.get("payment").is_some() {
            &mut m["payment"]
        } else {
            &mut m
        };
        t["mode"] = json!(mode);
        t["relayer"] = json!(who);
        t["feeRecipient"] = json!(who);
        m
    };
    for (name, o) in v["ops"].as_object().unwrap() {
        let Some(d) = o["domains"].get(kind) else {
            continue;
        };
        let m = &o["message"];
        let has_mode = m
            .get("feeRecipient")
            .or_else(|| m.get("payment").and_then(|p| p.get("feeRecipient")))
            .is_some();
        if d.get("calldata").is_none()
            || !has_mode
            || matches!(name.as_str(), "UACreateToken" | "UACreateDex")
        {
            continue;
        }
        let r = rows
            .iter()
            .find(|r| r.name == name && r.kinds.contains(&kind))
            .unwrap();
        let x = Value::Object(extra_of(name, r.plan, d));
        let sig = sig_of(sig_form(name, kind, r.plan), &d["signature"]);
        let at = b20(&d["domain"]["verifyingContract"]);
        let zero = "0x0000000000000000000000000000000000000000";
        let beef = "0x00000000000000000000000000000000deadbeef";
        let base = entry(name, kind, &at, &at_mode(m, 0, zero), &x, &sig).unwrap();
        let b = entry(name, kind, &at, &at_mode(m, 0, beef), &x, &sig).unwrap();
        assert_eq!(
            (&b.calldata, &b.op, &b.message),
            (&base.calldata, &base.op, &base.message),
            "{name} on {kind}: unbound zeroed"
        );
        assert!(
            !hex::encode(&b.calldata).contains("deadbeef"),
            "{name} on {kind}: an unbound value sent"
        );
        // control: mode 3 binds both: the named relayer is sent
        let c = entry(name, kind, &at, &at_mode(m, 3, beef), &x, &sig).unwrap();
        assert!(
            hex::encode(&c.calldata).contains("deadbeef"),
            "{name} on {kind}: a bound relayer is sent"
        );
        checked += 1;
    }
    assert!(checked > 0, "{kind}: no row with a fee mode");
}

/// Refusals by name, each with its control: an unknown field, a missing one, an unknown extra, a wrong signature form.
fn refusals(kind: &str, name: &str) {
    let v = ops();
    let o = &v["ops"][name];
    let d = &o["domains"][kind];
    let r = entry_rows()
        .into_iter()
        .find(|r| r.name == name && r.kinds.contains(&kind))
        .unwrap();
    let x = Value::Object(extra_of(name, r.plan, d));
    let form = sig_form(name, kind, r.plan);
    let sig = sig_of(form, &d["signature"]);
    let at = b20(&d["domain"]["verifyingContract"]);
    assert!(
        entry(name, kind, &at, &o["message"], &x, &sig).is_ok(),
        "control"
    );
    let mut m = o["message"].clone();
    m["data"] = json!("0x00");
    assert_eq!(
        entry(name, kind, &at, &m, &x, &sig),
        Err(Error::Argument),
        "{name}: an unknown field"
    );
    let mut m = o["message"].clone();
    let first = m.as_object().unwrap().keys().next().unwrap().clone();
    m.as_object_mut().unwrap().remove(&first);
    assert_eq!(
        entry(name, kind, &at, &m, &x, &sig),
        Err(Error::Argument),
        "{name}: {first} missing"
    );
    let mut y = x.clone();
    y["calldata"] = json!("0x00");
    assert_eq!(
        entry(name, kind, &at, &o["message"], &y, &sig),
        Err(Error::Argument),
        "{name}: an unknown extra"
    );
    let wrong = if form == "bytes" {
        sig_of("UASig", &d["signature"])
    } else {
        d["signature"].clone()
    };
    assert_eq!(
        entry(name, kind, &at, &o["message"], &x, &wrong),
        Err(Error::Argument),
        "{name}: the other signature form"
    );
    assert_eq!(
        entry(name, "nope", &at, &o["message"], &x, &sig),
        Err(Error::Argument),
        "{name}: no such kind"
    );
}

#[test]
fn entries_token() {
    table_both_ways("token");
    assert_eq!(
        vector_pairs("token"),
        15,
        "every token pair of typed_ops.json"
    );
    canon_unbound("token");
    refusals("token", "UAUnwrap");
    refusals("token", "Wrap");
    // two node rows with no row of typed_ops.json (`mtxPay`, the token's `mtxInvalidateNonces`): held to the node's table above
    let rows: BTreeSet<_> = entry_rows()
        .into_iter()
        .filter(|r| r.kinds.contains(&"token"))
        .map(|r| r.name)
        .collect();
    assert!(rows.contains("UAMetaTransfer") && rows.contains("UAInvalidateNonces"));
}

#[test]
fn entries_zether() {
    table_both_ways("zether");
    assert_eq!(
        vector_pairs("zether"),
        28,
        "every zether pair of typed_ops.json"
    );
    canon_unbound("zether");
    refusals("zether", "UAZetherTransfer");
    refusals("zether", "ZetherRollOver");
}

#[test]
fn entries_pqz() {
    table_both_ways("pqz");
    assert_eq!(
        vector_pairs("pqz"),
        26,
        "every pqz pair of typed_ops.json with an entry (PqzAuth has none)"
    );
    canon_unbound("pqz");
    refusals("pqz", "UAPqzTransferSingle");
    refusals("pqz", "PqzRollOver");
    let v = ops();
    let o = &v["ops"]["UAPqzUnshield"];
    let d = &o["domains"]["pqz"];
    let r = entry_rows()
        .into_iter()
        .find(|r| r.name == "UAPqzUnshield")
        .unwrap();
    let mut x = extra_of("UAPqzUnshield", r.plan, d);
    let sig = sig_of("UASig", &d["signature"]);
    let at = b20(&d["domain"]["verifyingContract"]);
    // a debit takes its verdict: without it, refused (the node never fills a job's)
    let none: Map<String, Value> = x
        .iter()
        .filter(|(k, _)| *k != "pqzVerdict")
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    assert_eq!(
        entry(
            "UAPqzUnshield",
            "pqz",
            &at,
            &o["message"],
            &Value::Object(none),
            &sig
        ),
        Err(Error::Argument)
    );
    // a signed verdict (an OFFCHAIN token): the calldata carries it, the job names the verifier's part, never the verdict
    x["pqzVerdict"]["pqzVerdict"]["pqzVerifierEpoch"] = json!(2);
    x["pqzVerdict"]["pqzVerdict"]["validUntil"] = json!("1800000000");
    x["pqzVerdict"]["sig"]["signature"] = d["signature"].clone();
    x.insert("pqz_fee".into(), json!("7"));
    let b = entry(
        "UAPqzUnshield",
        "pqz",
        &at,
        &o["message"],
        &Value::Object(x),
        &sig,
    )
    .unwrap();
    let op = b.op.unwrap();
    assert_eq!(
        norm(&op["args"]["pqz_verdict"]),
        norm(&json!({"pqzVerifierEpoch": 2, "validUntil": "1800000000",
        "auth": {"keyData": "0x", "signature": d["signature"], "members": []}}))
    );
    assert_eq!(op["args"]["pqz_fee"], json!("7"));
    assert!(op["args"].get("pqzVerdict").is_none());
    assert_ne!(
        hex::encode(&b.calldata),
        d["calldata"].as_str().unwrap()[2..],
        "the signed verdict is in the calldata"
    );
    // PqzAuth: no entry of its own
    let pa = &v["ops"]["PqzAuth"];
    assert_eq!(
        entry(
            "PqzAuth",
            "pqz",
            &at,
            &pa["message"],
            &json!({}),
            &Value::Null
        ),
        Err(Error::Argument)
    );
}

#[test]
fn entries_wallet() {
    table_both_ways("wallet");
    assert_eq!(
        vector_pairs("wallet"),
        7,
        "every MandateWallet pair of typed_ops.json"
    );
    canon_unbound("wallet");
    refusals("wallet", "UASetMandate");
    refusals("wallet", "UAPayUnderMandate");
}

#[test]
fn entries_account() {
    table_both_ways("account");
    assert_eq!(
        vector_pairs("account"),
        7,
        "every SmartKeyAccount pair of typed_ops.json"
    );
    canon_unbound("account");
    refusals("account", "AddKey");
    refusals("account", "CancelNonce");
}

/// T8e (CTR-ACC-01): the counterfactual `SmartKeyAccount`, the EIP-1167 clone by CREATE2 under
/// `keccak256(abi.encode(firstKey, guardian))`, against the forge-pinned row (`SmartKeyAccount.t.sol`
/// `test_pinned_create2_vector`; clientkeys `predictAccount` reads the same file); one change at a time moves it.
#[test]
fn smart_key_account_address() {
    use k256::ecdsa::SigningKey;
    use scaas_ua::factory::{account_address, account_salt};
    let v = load("smartcontracts/evm/test/vectors/smart_key_account_create2.json");
    let mut sk = [0u8; 32];
    let k = bytes(&json!(format!(
        "0x{:0>64}",
        v["seedPrivateKey"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x")
    )));
    sk.copy_from_slice(&k);
    let point = SigningKey::from_slice(&sk)
        .unwrap()
        .verifying_key()
        .to_sec1_point(false);
    let addr = &scaas_ua::keccak256(&point.as_bytes()[1..])[12..];
    let mut x = [0u8; 32];
    x[12..].copy_from_slice(addr);
    let z = [0u8; 32];
    let guardian = b20(&v["guardian"]);
    let salt = account_salt(2, &x, &z, &z, &z, &guardian);
    assert_eq!(
        format!("0x{}", hex::encode(salt)),
        v["salt"].as_str().unwrap(),
        "salt"
    );
    let (factory, implementation) = (b20(&v["factory"]), b20(&v["implementation"]));
    let want = v["account"].as_str().unwrap().to_ascii_lowercase();
    assert_eq!(
        format!(
            "0x{}",
            hex::encode(account_address(&factory, &implementation, &salt))
        ),
        want,
        "the clone address"
    );
    let mut other = guardian;
    other[19] ^= 1;
    assert_ne!(
        account_salt(2, &x, &z, &z, &z, &other),
        salt,
        "another guardian, another salt"
    );
    assert_ne!(
        account_salt(1, &x, &z, &z, &z, &guardian),
        salt,
        "another key kind, another salt"
    );
    let mut f2 = factory;
    f2[0] ^= 1;
    assert_ne!(
        format!(
            "0x{}",
            hex::encode(account_address(&f2, &implementation, &salt))
        ),
        want,
        "another factory"
    );
    assert_ne!(
        format!(
            "0x{}",
            hex::encode(account_address(&factory, &factory, &salt))
        ),
        want,
        "another implementation"
    );
}

#[test]
fn entries_dex() {
    table_both_ways("dex");
    assert_eq!(vector_pairs("dex"), 1, "the DEX pair of typed_ops.json");
    refusals("dex", "CancelDexOrder");
    // the DEX's nonce invalidation (no row of typed_ops.json): forge's `dex_order_kat.json` `invalidate_calldata`
    let k = load("smartcontracts/evm/test/vectors/dex_order_kat.json");
    let want = bytes(&k["invalidate_calldata"]);
    let word = |i: usize| &want[4 + 32 * i..4 + 32 * (i + 1)];
    let from = format!("0x{}", hex::encode(&word(0)[12..]));
    let (batch, min) = (word(1)[31], word(2)[31]);
    let len = word(4)[31] as usize;
    let sig = format!("0x{}", hex::encode(&want[4 + 160..4 + 160 + len]));
    let msg = json!({"from": from, "batch": batch.to_string(), "minNonce": min.to_string()});
    let b = entry(
        "InvalidateNonces",
        "dex",
        &b20(&k["dex"]),
        &msg,
        &json!({}),
        &json!(sig),
    )
    .unwrap();
    assert_eq!(b.calldata, want, "mtxInvalidateNonces on the DEX");
    assert_eq!(b.op.unwrap()["signature"], json!(sig));
}

#[test]
fn entries_router() {
    table_both_ways("gov_router");
    assert_eq!(
        vector_pairs("gov_router"),
        // set-auditor (CTR-GOV-31): 60 -> 62, `UASetAuditorKey`, `UASetAuditorUA`; CTR-GOV-33 Change: 62 -> 63, `UACancelNonceFor`
        63,
        "every GovernanceRouter pair of typed_ops.json"
    );
    canon_unbound("gov_router");
    refusals("gov_router", "UASetGrant");
    refusals("gov_router", "UAApproveRelease");
    // the release approvals: calldata for self-relay, no job op (the node's NO_NODE_ROW); every other router row has one
    let rows = entry_rows();
    let no_op: BTreeSet<_> = rows
        .iter()
        .filter(|r| r.kinds.contains(&"gov_router") && !r.node)
        .map(|r| r.name)
        .collect();
    assert_eq!(
        no_op,
        BTreeSet::from([
            "UAApproveTokenRelease",
            "UAApproveDexRelease",
            "UAApproveRelease",
            "UARevokeApproval"
        ])
    );
    // a generic creation by its initializer call: initHash = keccak256(init_call), the job names init_call, never initHash
    let v = ops();
    let o = &v["ops"]["UACreateInstance"];
    let d = &o["domains"]["gov_router"];
    let x = json!({"init_call": d["extra"]["initCall"]});
    let h = init_hash("UACreateInstance", "gov_router", &x)
        .unwrap()
        .unwrap();
    assert_eq!(h, scaas_ua::keccak256(&bytes(&d["extra"]["initCall"])));
    assert_eq!(
        format!("0x{}", hex::encode(h)),
        o["message"]["initHash"].as_str().unwrap()
    );
    let mut x2 = x.clone();
    x2["init_call"] = json!(format!("0x{}", "00".repeat(4097)));
    assert_eq!(
        init_hash("UACreateInstance", "gov_router", &x2),
        Err(Error::Argument),
        "an init_call above 4096 bytes"
    );
}

// --- owner 2026-11-18, ruling 6: the transfer on ids (`mtxExecuteTransfer`, `POST /v1/ua-metatx`) ---

/// A static ABI word of a JSON value of `ty`: `bytes32` / `address` hex, a decimal or number otherwise.
fn word_of(ty: &str, v: &Value) -> Vec<u8> {
    let mut w = vec![0u8; 32];
    match ty {
        "bytes32" | "address" => {
            let b = bytes(v);
            w[32 - b.len()..].copy_from_slice(&b);
        }
        _ => {
            let n: u128 = v.as_str().map_or_else(
                || v.as_u64().unwrap() as u128,
                |s| s.parse().unwrap_or(u128::MAX),
            );
            if n == u128::MAX {
                // a lane wider than u128: its 32 bytes from the decimal, by long multiplication
                let mut acc = vec![0u8; 32];
                for d in v.as_str().unwrap().bytes() {
                    let mut carry = u32::from(d - b'0');
                    for x in acc.iter_mut().rev() {
                        let t = u32::from(*x) * 10 + carry;
                        *x = t as u8;
                        carry = t >> 8;
                    }
                }
                return acc;
            }
            w[16..].copy_from_slice(&n.to_be_bytes());
        }
    }
    w
}

#[test]
fn entries_transfer_on_ids() {
    let v = load("smartcontracts/vectors/ua/metatx3.json");
    let row = v["transfer"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "native")
        .unwrap();
    let td = &row["typedData"];
    let token = b20(&td["domain"]["verifyingContract"]);
    let m = &td["message"];
    let sig = json!({"keyData": "0x", "signature": row["auth"], "members": []});
    let b = transfer_on_ids("token", &token, m, &sig).unwrap();
    // the selector: the contracts' published signature on every token kind (selector_audit.json, from the build)
    let abi = "mtxExecuteTransfer((bytes32,bytes32,uint256,bytes32,uint256,uint256,uint256,uint32,address,uint256,address),(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[]))";
    assert_eq!(b.calldata[..4], scaas_ua::keccak256(abi.as_bytes())[..4]);
    let audit = load("smartcontracts/evm/test/vectors/selector_audit.json");
    for c in [
        "NormalToken",
        "WrappedToken",
        "NormalZetherToken",
        "NormalPqzToken",
    ] {
        assert!(audit[c].to_string().contains(abi), "{c}: {abi}");
    }
    // the digest: the vector row's, over the canonical message
    assert_eq!(norm(&b.message), norm(m));
    let uid: [u8; 32] = bytes(&v["chainUid"]).try_into().unwrap();
    let t = scaas_ua::wallet::scaas_typed_data(
        "UAMetaTransfer",
        Some("SCaaS MetaToken"),
        &token,
        31337,
        &uid,
        &b.message,
    )
    .unwrap();
    assert_eq!(
        format!("0x{}", hex::encode(t.digest().unwrap())),
        row["digest"].as_str().unwrap()
    );
    // the head: the struct's eleven words in place, then the offset of the UASig
    let fields = [
        "bytes32 from",
        "bytes32 to",
        "uint256 value",
        "bytes32 entryRef",
        "uint256 batch",
        "uint256 nonce",
        "uint256 validUntil",
        "uint32 mode",
        "address relayer",
        "uint256 fee",
        "address feeRecipient",
    ];
    for (i, f) in fields.iter().enumerate() {
        let (ty, n) = f.split_once(' ').unwrap();
        assert_eq!(
            b.calldata[4 + 32 * i..4 + 32 * (i + 1)],
            word_of(ty, &m[n])[..],
            "{n}"
        );
    }
    assert_eq!(
        b.calldata[4 + 32 * 11..4 + 32 * 12],
        word_of("uint256", &json!("384"))[..],
        "the UASig after 12 words"
    );
    // the UASig's encoding: the tail of a typed_ops row whose UASig follows ten head words (UACancelNonce: 8 + lane + offset)
    let o = ops();
    let d = &o["ops"]["UACancelNonce"]["domains"]["token"];
    let c = transfer_on_ids(
        "token",
        &token,
        m,
        &json!({"keyData": "0x", "signature": d["signature"], "members": []}),
    )
    .unwrap();
    assert_eq!(
        c.calldata[4 + 32 * 12..],
        bytes(&d["calldata"])[4 + 32 * 10..],
        "the UASig as the generator encodes it"
    );
    // the node's body of `POST /v1/ua-metatx` (gateway.rs `UaReq`, `chain` added by the client)
    let op = b.op.unwrap();
    assert_eq!(
        op,
        json!({"token": format!("0x{}", hex::encode(token)), "contract": "token", "struct": "transfer", "m": b.message,
        "auth": {"keyData": "0x", "signature": row["auth"], "members": []}})
    );
    let gw = std::fs::read_to_string(root("scaas-node/src/gateway.rs")).unwrap();
    let ua_req = gw
        .split("pub struct UaReq {")
        .nth(1)
        .unwrap()
        .split('}')
        .next()
        .unwrap();
    for k in ["token", "contract", "m", "auth"] {
        assert!(ua_req.contains(&format!("pub {k}:")), "UaReq has no {k}");
    }
    assert!(ua_req.contains("rename = \"struct\""));
    // the other token kinds; never a non-token domain (control: the token kind above)
    assert!(
        transfer_on_ids("zether", &token, m, &sig).is_ok()
            && transfer_on_ids("pqz", &token, m, &sig).is_ok()
    );
    assert_eq!(
        transfer_on_ids("wallet", &token, m, &sig),
        Err(Error::Argument)
    );
    // not a `/v1/op` row: the table's UAMetaTransfer stays `mtxPay`
    assert!(entry_rows()
        .iter()
        .filter(|r| r.name == "UAMetaTransfer")
        .all(|r| r.entry == "mtxPay"));
}

/// The named `meta` of a `paymeta.json` row (its body decoded by schema), the form `pay_meta_of` and the pay entries take.
fn named_meta(r: &Value) -> Value {
    let b = bytes(&r["body"]);
    let w = |i: usize| b[32 * i..32 * (i + 1)].to_vec();
    let num = |x: &[u8]| x.iter().fold(0u64, |a, y| a << 8 | u64::from(*y));
    let body = match r["schema"].as_u64().unwrap() {
        0 => Value::Null,
        1 => json!({"note": String::from_utf8(b.clone()).unwrap()}),
        2 => {
            let len = num(&w(2)) as usize;
            json!({"creditorRef": String::from_utf8(b[96..96 + len].to_vec()).unwrap(), "dueDate": num(&w(1)).to_string()})
        }
        3 => {
            json!({"chainId": num(&w(0)).to_string(), "target": format!("0x{}", hex::encode(w(1))), "callHash": format!("0x{}", hex::encode(w(2)))})
        }
        _ => json!({"ciphertext": r["body"]}),
    };
    let mut m =
        json!({"salt": r["salt"], "payNo": r["payNo"], "save": r["save"], "schema": r["schema"]});
    if !body.is_null() {
        m["body"] = body;
    }
    m
}

#[test]
fn pay_meta_of_paymeta_rows() {
    let rows = load("smartcontracts/vectors/metatx/paymeta.json");
    let mut n = 0;
    for r in rows.as_array().unwrap() {
        let m = pay_meta_of(&named_meta(r)).unwrap();
        assert_eq!(
            m.body,
            bytes(&r["body"]),
            "{}: the body built from its named form",
            r["name"]
        );
        let id = scaas_ua::pay::meta_pay_id_v3(&m);
        match r["accepted"].as_bool().unwrap() {
            true => assert_eq!(
                format!("0x{}", hex::encode(id.unwrap())),
                r["payId"].as_str().unwrap(),
                "{}",
                r["name"]
            ),
            false => assert!(id.is_err(), "{}: refused", r["name"]),
        }
        n += 1;
    }
    assert_eq!(n, 9);
    assert_eq!(
        pay_meta_of(&json!({"salt": "0x01", "body": "0xab"})),
        Err(Error::Argument),
        "a hex body refused"
    );
}

/// Part 3b item 7 (owner 2026-11-19): every row names an entry its kinds' contracts have, so a quote or a job never names an
/// entry the contract lacks. The contracts' entries are `selector_audit.json`'s (every non-view external of each artifact,
/// read by `SelectorAudit.t.sol` against the build) for the token kinds (Normal, Wrapped and their regulated variants: a
/// row holds when one of them has the entry), the router, the DEX and the smart-key account; the mandate wallet (not an
/// audit artifact) by its source. A row with a vector in `typed_ops.json` is held by its whole ABI signature (the selector),
/// the others by the entry's name.
#[test]
fn rows_name_entries_their_contracts_have() {
    let audit = load("smartcontracts/evm/test/vectors/selector_audit.json");
    let vectors = ops();
    let wallet = ["MandateWallet.sol", "WalletExecute.sol"]
        .map(|f| {
            std::fs::read_to_string(root(&format!("smartcontracts/evm/src/wallet/{f}"))).unwrap()
        })
        .concat()
        + &std::fs::read_to_string(root("smartcontracts/evm/src/metatx/UAMetaTxBase.sol")).unwrap();
    let arts = |kind: &str| -> Vec<&str> {
        match kind {
            "token" => vec![
                "NormalToken",
                "WrappedToken",
                "NormalRegulatedToken",
                "WrappedRegulatedToken",
            ],
            "zether" => vec![
                "NormalZetherToken",
                "WrappedZetherToken",
                "NormalZetherRegulatedToken",
                "WrappedZetherRegulatedToken",
            ],
            "pqz" => vec![
                "NormalPqzToken",
                "WrappedPqzToken",
                "NormalPqzRegulatedToken",
                "WrappedPqzRegulatedToken",
            ],
            "gov_router" => vec!["GovernanceRouter"],
            "dex" => vec!["SCaaSDex"],
            "account" => vec!["SmartKeyAccount"],
            _ => vec![],
        }
    };
    let mut held = 0;
    for r in entry_rows().iter().filter(|r| !r.entry.is_empty()) {
        for kind in r.kinds {
            // the vector's signature is the row's own (`vector_pairs` holds the calldata the row builds equal to it)
            let abi = vectors["ops"][r.name]["domains"][*kind]["abi"].as_str();
            assert!(
                abi.is_none_or(|a| a.starts_with(&format!("{}(", r.entry))),
                "{} on {kind}: the vector's {abi:?} is not {}",
                r.name,
                r.entry
            );
            let have = |art: &str| -> bool {
                audit[art].as_array().unwrap().iter().any(|f| {
                    let sig = f["sig"].as_str().unwrap();
                    match abi {
                        Some(a) => sig == a,
                        None => sig.split('(').next() == Some(r.entry),
                    }
                })
            };
            let ok = match *kind {
                "wallet" => wallet.contains(&format!("function {}(", r.entry)),
                k => arts(k).into_iter().any(have),
            };
            assert!(
                ok,
                "{} on {kind}: {} ({abi:?}) is not an entry of the kind's contracts",
                r.name, r.entry
            );
            held += 1;
        }
    }
    assert!(held > 100, "{held} rows held");
}

// --- scaas-sdk T13: the registry writes ---

/// The registry rows are the node's `PLAIN` rows on `REG`, both ways (entry and fields), and the node's pinned selectors.
#[test]
fn registry_rows_equal_the_node() {
    use scaas_ua::wallet::entries::registry_rows;
    let src = std::fs::read_to_string(root("scaas-node/src/typed.rs")).unwrap();
    let head = "const PLAIN: &[(&str, &[&str], &str)] = &[";
    let i = src.find(head).unwrap();
    let rest = &src[i + head.len()..];
    let theirs: BTreeMap<String, String> = tuples(&rest[..rest.find("\n];").unwrap()])
        .into_iter()
        .filter(|t| t[1] == "REG")
        .map(|t| (t[0].clone(), t[2].clone()))
        .collect();
    let ours: BTreeMap<String, String> = registry_rows()
        .into_iter()
        .map(|r| (r.entry.to_string(), r.fields.to_string()))
        .collect();
    assert_eq!(ours, theirs, "the registry rows are the node's, both ways");
    // the node pins these (scaas-node/src/submit.rs, the UA-8 selector test)
    let sel = |e: &str| {
        let r = registry_rows().into_iter().find(|r| r.entry == e).unwrap();
        hex::encode(&scaas_ua::keccak256(r.signature.as_bytes())[..4])
    };
    assert_eq!(sel("registerWebAuthn"), "ee03a1fe");
    assert_eq!(sel("setKemKey"), "6a3318f9");
    assert_eq!(sel("storePqzPop"), "9f7be2a3");
}

/// Every registration row of `ua/portable.json` encodes; its length is `RegisterArgs::calldata_len`'s (an independent count)
/// for the single-key rows; a KEM record's `setKemKey` encodes; a field missing or unknown, or another entry, is `Argument`.
#[test]
fn registry_calls_of_portable_rows() {
    use scaas_ua::ua_portable::{registration_args, RegistrationInput};
    use scaas_ua::wallet::entries::registry_call;
    let v = load("smartcontracts/vectors/ua/portable.json");
    let mut n = 0;
    for r in v["registrations"].as_array().unwrap() {
        let a = &r["args"];
        let entry = a["entry"].as_str().unwrap();
        let cd = registry_call(entry, a).unwrap_or_else(|e| panic!("{}: {e:?}", r["name"]));
        if entry != "registerMsig" {
            let reg = registration_args(&RegistrationInput {
                kind: r["kind"].as_u64().unwrap() as u16,
                key_data: bytes(&r["keyData"]),
                pqz_key: bytes(&r["attrs"]["pqzKey"]),
                pqz_pop: bytes(&a["pqzPop"]),
                kem_pk: bytes(&r["attrs"]["kemPk"]),
                pop: bytes(&a["pop"]),
                kem_commit: Some(false),
                ..Default::default()
            })
            .unwrap();
            assert_eq!(cd.len(), reg.args.calldata_len(), "{}", r["name"]);
        }
        n += 1;
    }
    assert!(n >= 20, "{n} registration rows");
    for r in v["kemRecords"].as_array().unwrap() {
        registry_call("setKemKey", &r["args"]).unwrap_or_else(|e| panic!("{}: {e:?}", r["name"]));
    }
    let a = &v["registrations"][1]["args"];
    let mut missing = a.clone();
    missing.as_object_mut().unwrap().remove("pqzPop");
    assert_eq!(registry_call("register", &missing), Err(Error::Argument));
    let mut extra = a.clone();
    extra["memo"] = json!("0x");
    assert_eq!(registry_call("register", &extra), Err(Error::Argument));
    assert_eq!(registry_call("registerMsig", a), Err(Error::Argument));
    assert!(registry_call("register", a).is_ok(), "the control");
}
