// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! ua-mtx-merge T34 (regulated-kinds spec §3.1, §3.6, §5, §7): `scaas_ua::regulated` against the files clientkeys and forge
//! write: the router's eight regulated `UA<Op>` rows of `typed/typed_ops.json` (type string, struct hash, digest, a non-zero
//! unbound `relayer` / `feeRecipient` hashed as 0), each op built as its typed struct from the row's named fields (T21 L45;
//! under feature `vectors` also against the named op table, `scaas_typed_data`), and `governance/regulated_kat.json`'s
//! `recordId`, `R` and `commit` rows.
use scaas_ua::regulated::{
    can_receive, digest, record_id, relax_commit, router_domain_separator, struct_hash, type_string, Attestation, Envelope,
    GrantTerms, RegulatedOp, UAForceTransfer, UAFreeze, UAOperatorTransfer, UAPause, UARecordOrder, UARevokeOrder, UAUnfreeze,
    UAUnpause, REGULATED_OPS,
};
use serde_json::Value;

fn load(path: &str) -> Value {
    let path = format!("{}/../../smartcontracts/vectors/{path}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}
fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}
fn b32(v: &Value) -> [u8; 32] {
    bytes(v).try_into().unwrap()
}
fn b20(v: &Value) -> [u8; 20] {
    bytes(v).try_into().unwrap()
}
fn num(v: &Value) -> u128 {
    v.as_u64().map(u128::from).unwrap_or_else(|| v.as_str().unwrap().parse().unwrap())
}
/// A uint field of the JSON (a number or a decimal string) as its ABI word.
fn uint_word(v: &Value) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&num(v).to_be_bytes());
    w
}
fn envelope(m: &Value) -> Envelope {
    Envelope {
        from: b32(&m["from"]),
        batch: uint_word(&m["batch"]),
        nonce: uint_word(&m["nonce"]),
        valid_until: uint_word(&m["validUntil"]),
        mode: num(&m["mode"]) as u32,
        relayer: b20(&m["relayer"]),
        fee: uint_word(&m["fee"]),
        fee_recipient: b20(&m["feeRecipient"]),
    }
}
/// A Rust field name in the type string's form (`chain_uid` -> `chainUid`, `r#ref` -> `ref`).
fn camel(f: &str) -> String {
    let mut out = String::new();
    let mut up = false;
    for c in f.trim_start_matches("r#").chars() {
        if c == '_' {
            up = true;
        } else {
            out.push(if up { c.to_ascii_uppercase() } else { c });
            up = false;
        }
    }
    out
}

/// One row: the struct's fields are the type string's, by name and order; type string, struct hash and digest; a non-zero
/// relayer and fee recipient left unbound (mode 0, and the row's mode 1 with its fee recipient unbound) give the canonical
/// digest; the mode itself is signed. Under `vectors`: the named op table (`scaas_typed_data` of the row's message) agrees.
fn check<O: RegulatedOp>(op: &O, r: &Value) {
    let name = O::NAME;
    let (_, list) = REGULATED_OPS.iter().find(|(n, _)| *n == name).unwrap();
    let names: Vec<&str> = list.split(',').map(|f| f.split_once(' ').unwrap().1).collect();
    assert_eq!(O::FIELDS.iter().map(|f| camel(f)).collect::<Vec<_>>(), names, "{name}: the struct's fields");
    assert_eq!(type_string(name).unwrap(), r["typeString"].as_str().unwrap(), "{name}");
    let m = &r["message"];
    let d = &r["domains"]["gov_router"];
    let dom = &d["domain"];
    assert_eq!(dom["name"], "SCaaS GovernanceRouter");
    let ds = router_domain_separator(num(&dom["chainId"]) as u64, &b20(&dom["verifyingContract"]), &b32(&dom["salt"]));
    assert_eq!(ds, b32(&d["domainSeparator"]), "{name}");
    let (e, target) = (envelope(m), b20(&m["target"]));
    assert_eq!(struct_hash(op, &e, &target), b32(&r["structHash"]), "{name}");
    assert_eq!(digest(op, &ds, &e, &target), b32(&d["digest"]), "{name}");
    assert_eq!(e.mode, 1, "{name}: the router's fee mode NONE, the relayer bound");
    let junk = [0xba; 20];
    let fee_to = Envelope { fee_recipient: junk, ..e };
    assert_eq!(digest(op, &ds, &fee_to, &target), b32(&d["digest"]), "{name}: unbound feeRecipient");
    let open = |relayer, fee_recipient| digest(op, &ds, &Envelope { mode: 0, relayer, fee_recipient, ..e }, &target);
    assert_eq!(open(junk, junk), open([0; 20], [0; 20]), "{name}: mode 0");
    assert_ne!(open([0; 20], [0; 20]), b32(&d["digest"]), "{name}: the mode is signed");
    let bound = Envelope { relayer: junk, ..e };
    assert_ne!(digest(op, &ds, &bound, &target), b32(&d["digest"]), "{name}: a bound relayer is signed");
    #[cfg(feature = "vectors")]
    {
        let td = scaas_ua::wallet::scaas_typed_data(name, Some("SCaaS GovernanceRouter"), &b20(&dom["verifyingContract"]),
            num(&dom["chainId"]) as u64, &b32(&dom["salt"]), m)
        .unwrap();
        assert_eq!(td.digest().unwrap(), digest(op, &ds, &e, &target), "{name}: the named op table");
    }
}

/// Every one of the eight rows, each op built by name from the row's message.
#[test]
fn typed_ops_regulated_rows() {
    let v = load("typed/typed_ops.json");
    assert_eq!(REGULATED_OPS.len(), 8);
    let row = |op: &str| v["ops"][op].clone();
    let w = |op: &str, f: &str| -> [u8; 32] {
        let x = &v["ops"][op]["message"][f];
        if x.as_str().is_some_and(|s| s.starts_with("0x")) { b32(x) } else { uint_word(x) }
    };
    let n = |op: &str, f: &str| num(&v["ops"][op]["message"][f]) as u64;
    let mut done = 0;
    for (op, _) in REGULATED_OPS {
        let r = row(op);
        match op {
            "UAFreeze" => check(&UAFreeze { account: w(op, "account"), r#ref: w(op, "ref"), record_id: w(op, "recordId"),
                chain_uid: w(op, "chainUid") }, &r),
            "UAUnfreeze" => check(&UAUnfreeze { account: w(op, "account"), r#ref: w(op, "ref"), chain_uid: w(op, "chainUid") }, &r),
            "UAForceTransfer" => check(&UAForceTransfer { record_id: w(op, "recordId"), amount: w(op, "amount"),
                chain_uid: w(op, "chainUid") }, &r),
            "UAPause" => check(&UAPause { r#ref: w(op, "ref"), until: n(op, "until"), chain_uid: w(op, "chainUid") }, &r),
            "UAUnpause" => check(&UAUnpause { r#ref: w(op, "ref"), chain_uid: w(op, "chainUid") }, &r),
            "UARecordOrder" => check(&UARecordOrder { order_id: w(op, "orderId"), document_hash: w(op, "documentHash"),
                subject: w(op, "subject"), beneficiary: w(op, "beneficiary"), max_amount: w(op, "maxAmount"),
                freeze_until: n(op, "freezeUntil"), chain_uid: w(op, "chainUid") }, &r),
            "UARevokeOrder" => check(&UARevokeOrder { record_id: w(op, "recordId"), reason_ref: w(op, "reasonRef"),
                chain_uid: w(op, "chainUid") }, &r),
            "UAOperatorTransfer" => {
                let t = UAOperatorTransfer { account: w(op, "account"), to: w(op, "to"), amount: w(op, "amount"),
                    r#ref: w(op, "ref"), chain_uid: w(op, "chainUid") };
                check(&t, &r);
                // the moved account and the receiver are distinct in the row, so a swap is a different digest
                let e = envelope(&r["message"]);
                let swapped = UAOperatorTransfer { account: t.to, to: t.account, ..t.clone() };
                assert_ne!(struct_hash(&swapped, &e, &[0; 20]), struct_hash(&t, &e, &[0; 20]));
            }
            _ => panic!("{op}: no typed op"),
        }
        done += 1;
    }
    assert_eq!(done, 8);
    assert!(type_string("UAMint").is_none());
}

#[test]
fn regulated_kat_record_ids() {
    let k = load("governance/regulated_kat.json");
    let rows = k["recordId"].as_array().unwrap();
    assert!(rows.len() >= 3);
    for r in rows {
        assert_eq!(record_id(&b32(&r["orderId"]), &b32(&r["subject"]), &b32(&r["beneficiary"])), b32(&r["recordId"]), "{}", r["name"]);
    }
}

#[test]
fn regulated_kat_receiver_table() {
    let k = load("governance/regulated_kat.json");
    let rows = k["receiver"].as_array().unwrap();
    assert!(rows.len() >= 20);
    for r in rows {
        let a = Attestation {
            flags: num(&r["flags"]) as u64,
            valid_until: num(&r["validUntil"]) as u64,
            attester_enabled: r["kycProviderEnabled"].as_bool().unwrap(),
        };
        let kyc = r["kyc"].as_bool().unwrap(); // round 3s: both masks under bit 28
        let req = kyc.then(|| num(&r["requiredFlags"]) as u64);
        let den = kyc.then(|| num(&r["deniedFlags"]) as u64);
        let got = can_receive(req, den, &a, num(&r["now"]) as u64);
        assert_eq!(got, (r["ok"].as_bool().unwrap(), r["reason"].as_u64().unwrap() as u8), "{}", r["name"]);
    }
}

#[test]
fn regulated_kat_commits() {
    let k = load("governance/regulated_kat.json");
    let rows = k["commit"].as_array().unwrap();
    let mut actions: Vec<u8> = vec![];
    for r in rows {
        let action = r["action"].as_u64().unwrap() as u8;
        actions.push(action);
        let terms = r.get("terms").map(|t| GrantTerms {
            min: num(&t["min"]),
            max: num(&t["max"]),
            total: num(&t["total"]),
            per_window: num(&t["perWindow"]),
            window: num(&t["window"]) as u32,
            valid_until: num(&t["validUntil"]) as u64,
            max_uses: num(&t["maxUses"]) as u32,
            delegable: t["delegable"].as_bool().unwrap(),
            scope: b32(&t["scope"]),
        });
        let c = relax_commit(action, r["bit"].as_u64().unwrap() as u8, &b32(&r["account"]), terms.as_ref());
        assert_eq!(c, Some(b32(&r["commit"])), "{}", r["name"]);
    }
    actions.sort();
    actions.dedup();
    assert_eq!(actions, [1, 2, 3, 4, 5]);
    assert_eq!(relax_commit(2, 5, &[0; 32], None), None, "SET needs its terms");
    assert_eq!(relax_commit(6, 5, &[0; 32], None), None, "no action 6");
}

/// Round 3s (spec 2026-11-10-token-lists.md §4.3, §5.5): the list rows and the predicate rows of `regulated_kat.json`.
#[test]
fn regulated_kat_lists_and_enableable() {
    let k = load("governance/regulated_kat.json");
    let rows = k["lists"].as_array().unwrap();
    assert_eq!(rows.len(), 16);
    for r in rows {
        let got = scaas_ua::regulated::listed(num(&r["controls"]) as u8, num(&r["listFlags"]) as u8);
        assert_eq!(got, (r["ok"].as_bool().unwrap(), r["reason"].as_u64().unwrap() as u8), "{}", r["name"]);
    }
    let rows = k["enableable"].as_array().unwrap();
    assert!(rows.len() >= 9);
    for r in rows {
        let got = scaas_ua::regulated::enableable(num(&r["features"]) as u64, num(&r["lockedFeatures"]) as u64,
            num(&r["valid"]) as u64, r["admin"].as_bool().unwrap(), r["registry"].as_bool().unwrap());
        assert_eq!(got, num(&r["enableable"]) as u64, "{}", r["name"]);
    }
}
